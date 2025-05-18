from typing import Dict, Any, List
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()


class NetworkStatistics:
    """
    A service to manage network statistics across the application
    Provides a centralized way to update and retrieve network statistics
    """
    _instance = None

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize or reset network statistics"""
        # Tracking variables
        self.packet_counter = 0
        self.low_sev_count = 0
        self.med_sev_count = 0
        self.high_sev_count = 0
        self.in_size = 0
        self.out_size = 0
        self.ip = os.getenv("HOST_IP_ADDRESS", "194.233.72.57")

        # Distribution tracking
        self.protocol_distribution: Dict[str, int] = {}
        self.service_distribution: Dict[str, int] = {}
        self.attack_type_distribution: Dict[str, int] = {}

        # Top statistics tracking
        self.top_talkers: Dict[str, int] = {}
        self.top_ports: Dict[int, int] = {}
        self.top_attacked_ports: Dict[int, int] = {}
        self.top_attackers: Dict[str, int] = {}

        # Storage for non-normal packets (for MongoDB)
        self.non_normal_packets: List[Dict[str, Any]] = []

        # Storage for all packets
        self.all_packets: List[Dict[str, Any]] = []

    def __init__(self):
        """Ensure initialization for new instances"""
        if not hasattr(self, 'packet_counter'):
            self._initialize()

    def update_statistics(self, result_data: Dict[str, Any]):
        """
        Update network statistics and store non-normal packets

        :param additional_data: Additional packet details dictionary
        :param prediction: Prediction result dictionary
        """
        # print(result_data)
        # Severity count tracking
        if result_data["predicted_class"] == "Probe":
            self.low_sev_count += 1
        elif result_data["predicted_class"] == "Dos":
            self.med_sev_count += 1
        elif result_data["predicted_class"] in ["U2R", "R2L"]:
            self.high_sev_count += 1

        # Inbound/outbound size tracking
        if result_data["ipsrc"] == self.ip:
            self.in_size += result_data["len"]
        elif result_data["ipdst"] == self.ip:
            self.out_size += result_data["len"]

        # Protocol and service distribution
        self.protocol_distribution[result_data["protocol_type"]] = \
            self.protocol_distribution.get(
                result_data["protocol_type"], 0) + 1

        self.service_distribution[result_data["service"]] = \
            self.service_distribution.get(result_data["service"], 0) + 1

        # Top talkers, ports, and attackers tracking
        if result_data["ipdst"] == self.ip:
            # Top talkers by length
            self.top_talkers[result_data["ipsrc"]] = \
                self.top_talkers.get(
                    result_data["ipsrc"], 0) + result_data["len"]

            # Top ports
            self.top_ports[result_data["dport"]] = \
                self.top_ports.get(result_data["dport"], 0) + 1

            # Attack-specific tracking
            if result_data["predicted_class"] != "normal":
                self.top_attacked_ports[result_data["dport"]] = \
                    self.top_attacked_ports.get(
                        result_data["dport"], 0) + 1

                self.top_attackers[result_data["ipsrc"]] = \
                    self.top_attackers.get(result_data["ipsrc"], 0) + 1

                self.attack_type_distribution[result_data["predicted_class"]] = \
                    self.attack_type_distribution.get(
                        result_data["predicted_class"], 0) + 1

        # Store non-normal packets for MongoDB
        if result_data["predicted_class"] != "normal":
            self.non_normal_packets.append(result_data)

        # Store all packets
        self.all_packets.append(result_data)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Retrieve current network statistics

        :return: Dictionary of network statistics
        """
        # Prepare sorted and limited top statistics
        top_talk = dict(sorted(self.top_talkers.items(),
                        key=lambda item: item[1], reverse=True)[:10])
        top_ports = dict(sorted(self.top_ports.items(),
                         key=lambda item: item[1], reverse=True)[:10])
        top_attacked_ports = dict(sorted(
            self.top_attacked_ports.items(), key=lambda item: item[1], reverse=True)[:10])
        top_attackers = dict(sorted(self.top_attackers.items(
        ), key=lambda item: item[1], reverse=True)[:10])

        # Prepare the statistics dictionary
        stats = {
            "type": "batch_update",
            "pkt_in": self.in_size,
            "pkt_out": self.out_size,
            "low_count": self.low_sev_count,
            "med_count": self.med_sev_count,
            "high_count": self.high_sev_count,
            "protocols_count": self.protocol_distribution,
            "services_count": self.service_distribution,
            "top_talkers": top_talk,
            "top_ports": top_ports,
            "top_attacked_ports": top_attacked_ports,
            "top_attackers": top_attackers,
            "attack_type_count": self.attack_type_distribution,
        }

        return stats

    def get_non_normal_packets(self) -> List[Dict[str, Any]]:
        """
        Retrieve non-normal packets for MongoDB storage

        :return: List of non-normal packets
        """
        packets = self.non_normal_packets.copy()
        self.non_normal_packets.clear()
        return packets
    
    def get_all_packets(self) -> List[Dict[str, Any]]:
        """
        Retrieve all packets

        :return: List of all packets
        """
        packets = self.all_packets.copy()
        self.all_packets.clear()
        return packets

    def _reset_transient_stats(self):
        """
        Reset transient statistics after broadcasting
        """
        self.low_sev_count = 0
        self.med_sev_count = 0
        self.high_sev_count = 0
        self.in_size = 0
        self.out_size = 0
        self.protocol_distribution.clear()
        self.service_distribution.clear()
        self.attack_type_distribution.clear()
        self.top_talkers.clear()
        self.top_ports.clear()
        self.top_attacked_ports.clear()
        self.top_attackers.clear()

    def reset_statistics(self):
        """
        Reset all network statistics
        """
        self._initialize()


# Global service instance
network_stats_service = NetworkStatistics()
