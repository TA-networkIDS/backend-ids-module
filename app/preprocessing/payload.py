from typing import Dict, Any
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime


def create_broadcast_payload(packet_data: Dict[str, Any], prediction_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a broadcast payload by combining packet data and prediction result.

    Args:
        packet_data: Dictionary containing packet data with features and rawBytes
        prediction_result: Dictionary containing the model's prediction result

    Returns:
        Dictionary containing the combined data ready for broadcasting
    """
    # Start with the original packet data
    # payload = packet_data.copy()

    payload = {}
    # Common fields beteween data needed by FE and Models
    payload.update({
        "protocol_type": packet_data["protocol_type"],
        "service": packet_data["service"],
        "flag": packet_data["flag"],
    })

    # Reconstruct missing fields from rawBytes
    if 'rawBytes' in packet_data:
        pkt = Ether(bytes.fromhex(packet_data['rawBytes']))
        # print(pkt.summary())
        if IP in pkt:
            ip = pkt[IP]
            transport = pkt.getlayer(TCP) or pkt.getlayer(
                UDP) or pkt.getlayer(ICMP)

            # Add missing fields from packet reconstruction
            payload.update({
                'ipsrc': ip.src,
                'ipdst': ip.dst,
                'ttl': ip.ttl,
                'chksum': ip.chksum,
                'len': ip.len,
                'chksum_transport': getattr(transport, 'chksum', 0),
                'sport': getattr(transport, 'sport', 0),
                'dport': getattr(transport, 'dport', 0),
            })

            # # Convert timestamp to formatted string if it's a float
            # if isinstance(payload.get('timestamp'), float):
            #     payload['timestamp'] = datetime.fromtimestamp(
            #         payload['timestamp']).strftime("%Y-%m-%d, %H:%M:%S.%f")

    formatted_time = datetime.fromtimestamp(
        packet_data["timestamp"]).strftime("%Y-%m-%d, %H:%M:%S.%f")
    payload.update({
        "formatted_timestamp": formatted_time,
    })

    # Add prediction results
    payload.update({
        "predicted_class": prediction_result["predicted_class"],
        # Optional field
        "confidence": prediction_result.get("confidence", None),
    })

    # # Add any additional prediction details
    # payload.update({
    #     k: v for k, v in prediction_result.items()
    #     if k not in ["predicted_class", "confidence", "timestamp"]
    # })

    return payload
