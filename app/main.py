from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI
from app.api.routes import routes
from app.api.websockets import ws
from app.rmq import PikaClient
import threading
import asyncio
import logging
import logging.config

logging.basicConfig(level=logging.INFO)

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'myapp': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
logging.config.dictConfig(logging_config)
logger = logging.getLogger('myapp')
#  mongodb://root:example@mongo:27017/

def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
    # inspired from https://gist.github.com/dmfigol/3e7d5b84a16d076df02baa9f53271058
    asyncio.set_event_loop(loop)
    loop.run_forever()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # init rmq consumer when app starts
    logger.critical("Starting RMQ consumer")

    # attach rmq consumer to app
    app.rmq_consumer = PikaClient(queue_name="ids-queue", host="rabbitmq",
                                  port=5672, user="guest", password="guest")
    app.consumer_loop = asyncio.new_event_loop()
    tloop = threading.Thread(target=start_background_loop, args=(
        app.consumer_loop,), daemon=True)
    tloop.start()

    _ = asyncio.run_coroutine_threadsafe(
        app.rmq_consumer.start_consumer(), app.consumer_loop)

    yield
    # shutdown event
    await app.rmq_consumer.disconnect()
    app.consumer_loop.stop()


app = FastAPI(title="Detection Engine Module", debug=True, lifespan=lifespan)

app.include_router(routes.router)
app.include_router(ws.router)


@app.get("/")
async def root():
    return {"message": "IDS Backend is running."}


# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)
