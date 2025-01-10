Running the Docker Container

Build the Docker image:

    docker build -t fortress .

Run the Docker container:

    docker run -d -p 80:80 fortress

Check logs:

    docker logs <container_id>


