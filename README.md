# ghostline-relay-

A minimal in-memory relay broker.

## Usage

```python
from relay_broker import RelayBroker

broker = RelayBroker()


def on_message(payload):
    print(payload)


broker.subscribe("events", on_message)
broker.relay("events", {"type": "ping"})
```
