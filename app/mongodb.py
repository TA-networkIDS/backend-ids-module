import os
import asyncio
# from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import AsyncMongoClient
from typing import Dict, Any, List
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

logger = logging.getLogger("myapp")

class MongoDBClient:
    _instance = None

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
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
            # might need to delete the non_normal_packets collection
            self.non_normal_packets_collection = self.db["non_normal_packets"]
            self.network_statistics_collection = self.db["network_statistics"]
            self.packets_collection = self.db["all_packets"]

            logger.info("MongoDB connection initialized successfully")
        except Exception as e:
            logger.error(f"MongoDB connection error: {e}")
            raise

    async def insert_non_normal_packets(self, packets: List[Dict[str, Any]]):
        """
        Insert non-normal packets into MongoDB
        
        :param packets: List of non-normal packet dictionaries
        :return: Result of the insert operation
        """
        if not packets:
            return None

        try:
            result = await self.non_normal_packets_collection.insert_many(packets)
            # logger.info(f"Inserted {len(packets)} non-normal packets")
            return result
        except Exception as e:
            logger.error(f"Error inserting non-normal packets: {e}")
            return None

    async def update_network_statistics(self, statistics: Dict[str, Any]):
        """
        Update cumulative network statistics in MongoDB
        
        :param statistics: Dictionary of network statistics
        :return: Result of the update operation
        """
        try:
            # Use a fixed document ID for cumulative statistics
            document_id = "cumulative_network_stats"
            
            # Create update document
            update_doc = {
                "$set": {
                    "last_updated": datetime.now(),
                    "type": "batch_update",
                    # Store dictionaries directly
                    "protocols_count": statistics.get("protocols_count", {}),
                    "services_count": statistics.get("services_count", {}),
                    "attack_type_count": statistics.get("attack_type_count", {})
                },
                "$inc": {
                    "pkt_in": statistics.get("pkt_in", 0),
                    "pkt_out": statistics.get("pkt_out", 0),
                    "low_count": statistics.get("low_count", 0),
                    "med_count": statistics.get("med_count", 0),
                    "high_count": statistics.get("high_count", 0)
                }
            }
            
            # Handle top statistics - merge with existing values
            for top_stat in ["top_talkers", "top_ports", "top_attacked_ports", "top_attackers"]:
                if top_stat in statistics and statistics[top_stat]:
                    # Use $set with dot notation to update individual fields in the dictionary
                    for key, value in statistics[top_stat].items():
                        update_doc["$set"][f"{top_stat}.{key}"] = value
            
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

    async def get_non_normal_packets(self, time_range_minutes: int = 30):
        """
        Retrieve non-normal packets within a specified time range
        
        :param time_range_minutes: Time range in minutes to fetch packets (default: 30)
        :return: List of non-normal packets within the specified time range
        """
        try:
            # Calculate the time threshold
            time_threshold = datetime.now() - timedelta(minutes=time_range_minutes)
            
            # Query non-normal packets within the time range
            cursor = self.non_normal_packets_collection.find({
                "timestamp": {"$gte": time_threshold}
            })
            
            # Convert cursor to list
            packets = await cursor.to_list(length=None)
            
            logger.info(f"Retrieved {len(packets)} non-normal packets from the last {time_range_minutes} minutes")
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
                logger.info("Retrieved network statistics from database")
                return stats
            else:
                logger.warning("No network statistics found in database")
                return {}
        
        except Exception as e:
            logger.error(f"Error retrieving network statistics: {e}")
            return {}

# Global MongoDB client instance
mongodb_client = MongoDBClient()
