import os
import asyncio
from pymongo import AsyncMongoClient
from typing import Dict, Any, List
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta
import time

load_dotenv()

logger = logging.getLogger("myapp")


class MongoDBClient:
    def __init__(self):
        """Initialize MongoDB connection"""
        try:
            # MongoDB connection parameters from environment variables
            mongo_host = os.getenv("MONGO_HOST", "mongo")
            mongo_port = int(os.getenv("MONGO_PORT", 27017))
            mongo_user = os.getenv("MONGO_USERNAME", "root")
            mongo_password = os.getenv("MONGO_PASSWORD", "example")
            mongo_db = os.getenv("MONGO_DATABASE", "ids_database")

            # Construct connection string
            connection_string = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"

            self.client = AsyncMongoClient(connection_string)
            self.db = self.client[mongo_db]

            # Define collections
            self.non_normal_packets_collection = self.db["non_normal_packets"]
            self.network_statistics_collection = self.db["network_statistics"]
            self.packets_collection = self.db["all_packets"]

            logger.info("MongoDB connection initialized successfully")
        except Exception as e:
            logger.error(f"MongoDB connection error: {e}")
            raise

    async def insert_non_normal_packets(self, packet: Dict[str, Any]):
        """
        Insert non-normal packets into MongoDB

        :param packets: non-normal packet dictionaries
        :return: Result of the insert operation
        """
        result = await self.non_normal_packets_collection.insert_one(packet.copy())
        return result

    async def batch_insert_non_normal_packets(self, packets: List[Dict[str, Any]]):
        """
        Insert non-normal packets into MongoDB in batch

        :param packets: non-normal packet dictionaries
        :return: Result of the insert operation
        """
        result = await self.non_normal_packets_collection.insert_many(packets.copy())
        return result

    async def update_network_statistics(self, statistics: Dict[str, Any]):
        """
        Update cumulative network statistics in MongoDB

        :param statistics: Dictionary of network statistics
        :return: Result of the update operation
        """
        try:
            # Use a fixed document ID for cumulative statistics
            document_id = "cumulative_network_stats"
            # First get existing document to properly merge dictionaries
            existing_doc = await self.network_statistics_collection.find_one({"_id": document_id})

            # Create base update document with simple increments
            update_doc = {
                "$set": {"last_updated": datetime.now()},
                "$inc": {
                    "pkt_in": statistics.get("pkt_in", 0),
                    "pkt_out": statistics.get("pkt_out", 0),
                    "low_count": statistics.get("low_count", 0),
                    "med_count": statistics.get("med_count", 0),
                    "high_count": statistics.get("high_count", 0)
                }
            }

            # Handle dictionary fields that need accumulation
            for stat_field in ["protocols_count", "services_count", "attack_type_count",
                               "top_talkers", "top_ports", "top_attacked_ports", "top_attackers"]:
                new_values = statistics.get(stat_field, {})
                if new_values:
                    existing_values = existing_doc.get(
                        stat_field, {}) if existing_doc else {}

                    # Merge and accumulate values
                    for key, value in new_values.items():
                        # For IP addresses (in top_talkers and top_attackers), replace dots with (- dash)
                        # Mongodb does not allow dots in keys
                        if stat_field in ["top_talkers", "top_attackers"]:
                            key = key.replace(".", "-")

                        inc_path = f"{stat_field}.{key}"
                        if inc_path not in update_doc["$inc"]:
                            update_doc["$inc"][inc_path] = 0
                        update_doc["$inc"][inc_path] += value

            # Perform an upsert operation
            result = await self.network_statistics_collection.update_one(
                {"_id": document_id},
                update_doc,
                upsert=True
            )

            logger.info("Updated cumulative network statistics")
            return result
        except Exception as e:
            logger.error(f"Error updating network statistics: {e}")
            return None

    async def close(self):
        """Close MongoDB connection"""
        try:
            self.client.close()
            logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")

    async def get_non_normal_packets(self, minutes: int = 30):
        """
        Retrieve non-normal packets within a specified time range

        :param time_range_minutes: Time range in minutes to fetch packets (default: 30)
        :return: List of non-normal packets within the specified time range
        """
        try:
            current_time = time.time()

            # Calculate the timestamp from X minutes ago (in seconds)
            delta_time_seconds = current_time - (minutes * 60)

            # Query non-normal packets within the time range
            cursor = self.non_normal_packets_collection.find({
                "timestamp": {"$gte": delta_time_seconds}
            })

            # Convert cursor to list
            packets = await cursor.to_list(length=None)

            # format packets,pop _id field and convert timestamp to string
            for packet in packets:
                packet.pop("_id")
                packet["timestamp"] = str(packet["timestamp"])

            logger.info(
                f"Retrieved {len(packets)} non-normal packets from the last {minutes} minutes")
            return packets

        except Exception as e:
            logger.error(f"Error retrieving non-normal packets: {e}")
            return []

    async def get_network_statistics(self):
        """
        Retrieve current network statistics from the database

        :return: Dictionary of network statistics
        """
        try:
            # Retrieve the cumulative network statistics document
            stats = await self.network_statistics_collection.find_one({"_id": "cumulative_network_stats"})

            if stats:
                # Remove the _id field from the result
                stats.pop("_id", None)

                # Convert dashed back to normal dots in IP addresses
                for field in ["top_talkers", "top_attackers"]:
                    if field in stats:
                        converted = {}
                        for key, value in stats[field].items():
                            converted[key.replace("-", ".")] = value
                        stats[field] = converted

            # Sort and limit top_ports and top_attacked_ports to top 10
            for field in ["top_ports", "top_attacked_ports"]:
                if field in stats:
                    # Convert to list of tuples, sort by value (descending), and take top 10
                    sorted_items = sorted(stats[field].items(),
                                          key=lambda x: x[1],
                                          reverse=True)[:10]
                    # Convert back to dictionary
                    stats[field] = dict(sorted_items)

                logger.info("Retrieved network statistics from database")
                return stats
            else:
                logger.warning("No network statistics found in database")
                return {}

        except Exception as e:
            logger.error(f"Error retrieving network statistics: {e}")
            return {}
