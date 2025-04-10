# IDS with Infere
Example Network Packet Data.
Features from NSL-KDD Dataset.

## Data Input Example Format
```json
{
  "data": [
    {
      "duration": 0,
      "protocol_type": "tcp",
      "service": "smtp",
      "flag": "SF",
      "src_bytes": 914,
      "dst_bytes": 329,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "count": 2,
      "srv_count": 2,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 255,
      "dst_host_srv_count": 155,
      "dst_host_same_srv_rate": 0.61,
      "dst_host_diff_srv_rate": 0.06,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.01,
      "dst_host_srv_rerror_rate": 0.01
    }
    // ... more data points
  ]
}
```

## Data Output Example Format
```json
[
    {
        "predicted_class": "normal",
        "confidence": 0.9996503591537476
    }
    // ... more predictions
]
```