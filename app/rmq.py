import logging
from typing import Any, Dict
import aio_pika
import asyncio
import json
from app.models.model import predict as model_predict
from app.api.websockets.ws import manager as ws_manager
from app.network_statistics import network_stats_service
from dotenv import load_dotenv
import os
load_dotenv()

logger = logging.getLogger("myapp")


class PikaClient:
    def __init__(self, queue_name: str, host: str, port: int, user: str, password: str):
        self.queue_name = queue_name
        self.host = host
        self.port = port
        self.user = user
        self.password = password

        self.connection: aio_pika.RobustConnection = None
        self.channel: aio_pika.abc.AbstractChannel = None
        self.queue = None

        # batch processing test
        self.batch_size = 10
        self.message_batch = []
        self.batch_lock = asyncio.Lock()

        self.consumed_packet_counter = 0

    async def start_connection(self):
        try:
            logger.info("Starting RabbitMQ connection")
            self.connection = await aio_pika.connect_robust(
                host=self.host,
                port=self.port,
                login=self.user,
                password=self.password
            )

            self.channel = await self.connection.channel()
            await self.setup_queue()
        except Exception as e:
            logger.error(f"RabbitMQ connection error: {e}")

    async def setup_queue(self):
        logger.info(f"Setting up queue: {self.queue_name}")
        self.queue = await self.channel.declare_queue(name=self.queue_name, durable=True)

    async def start_consumer(self):
        await self.start_connection()
        # await self.channel.set_qos(prefetch_count=1)
        await self.channel.set_qos(prefetch_count=10)

        logger.info("Starting RabbitMQ consumer")
        try:
            await self.queue.consume(self.handle_message_batch, no_ack=False)
            # await self.queue.consume(self.handle_message, no_ack=False)
            # await self.queue.consume(self.handle_message, no_ack=True)
        except Exception as e:
            logger.error(f"Consumer start error: {e}")

        return self

    async def handle_message(self, message: aio_pika.abc.AbstractIncomingMessage):
        """Handle incoming packet message"""
        try:
            # Parse packet
            packet = json.loads(message.body)
            additional_data = packet["additional_data"]
            host_ip = os.getenv("HOST_IP_ADDRESS", "194.233.72.57")

            # Determine if packet is inbound or outbound
            if additional_data["ipdst"] == host_ip:
                # Inbound packet: run normal inference
                prediction_result = model_predict([packet])[0]
            else:
                # Outbound packet: set prediction to normal with 0 confidence
                prediction_result = {
                    "predicted_class": "normal",
                    "confidence": 0.0
                }

            # Combine additional data with prediction result
            result_data = {
                **additional_data,
                **prediction_result
            }

            # Create tasks for concurrent execution
            tasks = [
                asyncio.create_task(
                    network_stats_service.update_statistics(result_data))
            ]

            # Add broadcast task only for non-normal packets
            if prediction_result['predicted_class'] != 'normal':
                tasks.append(asyncio.create_task(
                    ws_manager.broadcast(result_data)))
                logger.warning(
                    f"[ALERT] Potential intrusion: {prediction_result['predicted_class']}")

            # Wait for all tasks to complete
            await asyncio.gather(*tasks)

            # Manual acknowledgement
            await message.ack()

        except Exception as e:
            logger.error(f"Message handling error: {e}")
            await message.nack(requeue=True)

    async def disconnect(self):
        try:
            if self.connection and not self.connection.is_closed:
                await self.connection.close()
        except Exception as e:
            logger.error(f"Disconnection error: {e}")

    async def process_message_batch(self, messages):
        """Process a batch of messages together"""
        try:
            # Extract packets from messages
            packets = [json.loads(msg.body) for msg in messages]
            host_ip = os.getenv("HOST_IP_ADDRESS", "194.233.72.57")

            # Split packets into inbound and outbound
            inbound_packets = []
            outbound_results = []

            for packet in packets:
                if packet["additional_data"]["ipdst"] == host_ip:
                    inbound_packets.append(packet)
                else:
                    outbound_results.append({
                        "predicted_class": "normal",
                        "confidence": 0.0,
                        **packet["additional_data"]
                    })

            # Batch predict inbound packets
            if inbound_packets:
                predictions = model_predict(inbound_packets)
                inbound_results = [
                    {**p["additional_data"], **pred}
                    for p, pred in zip(inbound_packets, predictions)
                ]
            else:
                inbound_results = []

            # Combine results
            all_results = inbound_results + outbound_results
            # Process statistics update in batch
            await network_stats_service.update_statistics_batch(all_results)

        # Handle broadcasts separately for non-normal packets
            broadcast_tasks = []
            for result in all_results:
                if result['predicted_class'] != 'normal':
                    # this make the broadcast task to be executed concurrently
                    broadcast_tasks.append(asyncio.create_task(
                        ws_manager.broadcast(result)
                    ))
                    logger.warning(
                        f"[ALERT] Potential intrusion: {result['predicted_class']}")

            if broadcast_tasks:
                await asyncio.gather(*broadcast_tasks)

            # Acknowledge all messages, one by one
            for message in messages:
                await message.ack()

            # logger.warning(f"Processed {self.consumed_packet_counter} packets")

        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            # Nack all messages on error
            for message in messages:
                await message.nack(requeue=True)

    async def handle_message_batch(self, message: aio_pika.abc.AbstractIncomingMessage):
        """Handle incoming packet message"""
        async with self.batch_lock:
            self.message_batch.append(message)
            self.consumed_packet_counter += 1

            if len(self.message_batch) >= self.batch_size:
                # Process the batch
                batch_to_process = self.message_batch
                self.message_batch = []
                await self.process_message_batch(batch_to_process)
