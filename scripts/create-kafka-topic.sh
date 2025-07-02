#!/bin/bash

echo "Checking and creating Kafka topic auth-events..."

# Get Kafka container ID
KAFKA_CONTAINER=$(docker ps | grep kafka | awk '{print $1}')

if [ -z "$KAFKA_CONTAINER" ]; then
    echo "Kafka container not found!"
    exit 1
fi

echo "Found Kafka container: $KAFKA_CONTAINER"

# Wait for Kafka to be ready
for i in {1..10}; do
    if docker exec $KAFKA_CONTAINER kafka-topics --list --bootstrap-server localhost:9092 >/dev/null 2>&1; then
        echo "Kafka is ready!"
        break
    fi
    echo "Waiting for Kafka... ($i/10)"
    sleep 2
done

# Create topic
echo "Creating topic auth-events..."
docker exec $KAFKA_CONTAINER kafka-topics --create --topic auth-events --partitions 1 --replication-factor 1 --if-not-exists --bootstrap-server localhost:9092
echo "Topic created!" 