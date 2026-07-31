# core/graph_scorer.py
# Graph-based anomaly scoring for the OSINT Pivot Engine.
# Builds a relationship graph from pivot results and scores
# indicators based on their network position and neighbor risk.

import logging
import networkx as nx

logger = logging.getLogger(__name__)

class GraphScorer:
    """
    Builds a directed graph from pivot results and scores
    based on their connectivity and neighbor risk profile.
    Higher scores = indicate deeper embeddeness in malicious
    infrastructure. 
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_scores = {}

    def reset(self):
        """Clears the graph between investigations."""
        self.graph.clear()
        self.node_scores.clear()

    def build_graph(self, pivot_results: list) -> None:
        """
        Constructs directed graph from list of pivot results
        Nodes = indicators; Edges = represent discovered relationships
        and certificate co-occurrence 
        """
        for pivot in pivot_results:
            indicator = pivot.get("indicator", "")
            indicator_type = pivot.get("type","")
            results = pivot.get("results", {})

            if not indicator:
                continue

             # Add node with metadata
            malicious_votes = results.get("virustotal", {}).get("malicious_votes", 0)
            harmless_votes = results.get("virustotal", {}).get("harmless_votes", 0)
            total = malicious_votes + harmless_votes
            malicious_ratio = malicious_votes / total if total > 0 else 0.0

            self.graph.add_node(indicator, 
                type=indicator_type,
                malicious_ratio=malicious_ratio,
                malicious_votes=malicious_votes
            )

            # Passive DNS edges — domain resolves to IP
            passivedns = results.get("passivedns", {})
            for record in passivedns.get("records", []):
                related = record.get("ip") or record.get("domain", "")
                if related and related != indicator:
                    self.graph.add_node(related)
                    self.graph.add_edge(indicator, related, 
                        relationship="passive_dns")

            # MalwareBazaar edges — hash shares malware family with related samples
            bazaar_related = results.get("malwarebazaar_related", {})
            for sample in bazaar_related.get("samples", []):
                sha256 = sample.get("sha256", "")
                if sha256 and sha256 != indicator:
                    self.graph.add_node(sha256)
                    self.graph.add_edge(indicator, sha256,
                        relationship="malware_cluster")

            # Certificate edges — domain shares cert with other names
            censys = results.get("censys", {})
            for cert in censys.get("certificates", []):
                names = cert.get("names", "")
                for name in names.replace("\n", ",").split(","):
                    name = name.strip().lstrip("*.")
                    if name and name != indicator:
                        self.graph.add_node(name)
                        self.graph.add_edge(indicator, name,
                            relationship="certificate")

    def score_node(self, indicator: str) -> float:
        """
        Method does the following:
        Scores a single indicator based on its position in the graph
        Considers the following signals:
        Degree: how many connections this indicator has
        Neighbor malicious ratio: how suspicious its neighbors are
        Clustering: how tightly connected its neighborhood is
        """
        if indicator not in self.graph:
            return 0.0

        # Degree score — more connections = higher risk
        degree = self.graph.degree(indicator)
        max_degree = max(dict(self.graph.degree()).values()) if self.graph.number_of_nodes() > 0 else 1
        degree_score = degree / max_degree if max_degree > 0 else 0.0

        # Neighbor malicious ratio — how bad are the neighbors
        neighbors = list(self.graph.neighbors(indicator))
        if neighbors:
            neighbor_ratios = [
                self.graph.nodes[n].get("malicious_ratio", 0.0)
                for n in neighbors
                if n in self.graph.nodes
            ]
            neighbor_score = sum(neighbor_ratios) / len(neighbor_ratios) if neighbor_ratios else 0.0
        else:
            neighbor_score = 0.0

        # Clustering coefficient — how interconnected the neighborhood is
        try:
            undirected = self.graph.to_undirected()
            clustering = nx.clustering(undirected, indicator)
        except Exception:
            clustering = 0.0

        # Weighted composite
        graph_score = (
            degree_score * 0.4 +
            neighbor_score * 0.4 +
            clustering * 0.2
        )

        return round(min(graph_score, 1.0), 4)

    def score_all(self, pivot_results: list) -> dict:
        """
        Builds the graph and scores all investigated indicators.
        Returns a dict mapping each indicator to its graph score.
        """
        self.reset()
        self.build_graph(pivot_results)

        scores = {}
        for pivot in pivot_results:
            indicator = pivot.get("indicator", "")
            if indicator:
                scores[indicator] = self.score_node(indicator)
                self.node_scores[indicator] = scores[indicator]

        logger.info(f"Graph scoring complete. Scored {len(scores)} indicators across {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")

        return scores

    def blend_scores(self, ml_score: float, graph_score: float) -> float:
        """
        Blends the ML confidence score with the graph score.
        Weights: 70% ML, 30% graph.
        Graph score acts as an amplifier for borderline indicators.
        """
        blended = (ml_score * 0.7) + (graph_score * 0.3)
        return round(min(blended, 1.0), 4)