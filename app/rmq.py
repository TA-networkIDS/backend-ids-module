import logging
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
        await self.channel.set_qos(prefetch_count=1)

        logger.info("Starting RabbitMQ consumer")
        try:
            # await self.queue.consume(self.handle_message, no_ack=False)
            await self.queue.consume(self.handle_message, no_ack=True)
        except Exception as e:
            logger.error(f"Consumer start error: {e}")

        return self

    async def handle_message(self, message: aio_pika.abc.AbstractIncomingMessage):
        """Handle incoming packet message"""
        try:
            # Parse packet
            packet = json.loads(message.body)
            # print(packet)
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

            # Update network statistics via service
            network_stats_service.update_statistics(result_data)

            # Broadcast for all traffic but ignore outbound packet
            if prediction_result['confidence'] != 0.0:
                # Prepare alert payload
                alert_payload_all = json.dumps(result_data)

                # Broadcast to WebSocket clients
                await ws_manager.broadcast_all(alert_payload_all)

            # Broadcast only non-normal packets via WebSocket
            if prediction_result['predicted_class'] != 'normal':
                # Prepare alert payload
                alert_payload = json.dumps(result_data)

                # Broadcast to WebSocket clients
                await ws_manager.broadcast(alert_payload)

                print(
                    f"[ALERT] Potential intrusion: {prediction_result['predicted_class']}")

            # Manual acknowledgement
            # await message.ack()

        except Exception as e:
            logger.error(f"Message handling error: {e}")
            await message.nack(requeue=True)

    async def disconnect(self):
        try:
            if self.connection and not self.connection.is_closed:
                await self.connection.close()
        except Exception as e:
            logger.error(f"Disconnection error: {e}")
