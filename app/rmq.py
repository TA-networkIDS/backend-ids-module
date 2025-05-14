import logging
import aio_pika
import asyncio
import json
from app.models.model import predict as model_predict
from app.preprocessing.payload import create_broadcast_payload
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
        self.packet_counter = 0

    async def start_connection(self):
        try:
            logger.info("Starting a new connection")
            self.connection = await aio_pika.connect_robust(host=self.host, port=self.port, login=self.user, password=self.password)

            logger.info("Opening channel")
            self.channel = await self.connection.channel()

            await self.setup_queue()
        except Exception as e:
            logger.error(e)

    async def setup_queue(self):
        logger.info("Setup a queue: %s" % self.queue_name)
        self.queue = await self.channel.declare_queue(name=self.queue_name, durable=True)

    async def start_consumer(self):
        await self.start_connection()

        await self.channel.set_qos(prefetch_count=1)

        logger.info("Starting consumer")
        try:
            await self.queue.consume(self.handle_message, no_ack=False)
        except Exception as _e:
            print(_e)
            logger.error(_e)
        print("here")
        logger.info("Consumer has been started")
        return self

    async def handle_message(self, message: aio_pika.abc.AbstractIncomingMessage):
        """Handle incoming message"""

        # TODO: pass to model and broadcast
        # await asyncio.sleep(3)
        # print(json.loads(message.body))
        self.packet_counter += 1
        # logger.info("total packets recieved: %s" % self.packet_counter)

        packet = json.loads(message.body)
        prediction_result = model_predict([packet])[0]
        print(prediction_result)





        # manual ack mechanism to tell broker that the message has been processed properly
        await message.ack()


    async def disconnect(self):
        try:
            if not self.connection.is_closed:
                await self.connection.close()
        except Exception as _e:
            logger.error(_e)
