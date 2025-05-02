# Secure your MCP Gateway and Registry

A fully functional nginx configuration file is available [here](examples/nginx_rev_proxy.conf) in the examples folder for use as a reference i.e. you would need to edit this configuration file as per the information provided below.

1. Enable access to TCP port 443 from the IP address of your MCP client (your laptop, or anywhere) in the inbound rules in the security group associated with your EC2 instance.

1. You would need to have an HTTPS certificate and private key to proceed. Let's say you use `your-mcp-server-domain-name.com` as the domain for your MCP server then you will need an SSL cert for `your-mcp-server-domain-name.com` and it will be accessible to MCP clients as `https://your-mcp-server-domain-name.com/sse`. _While you can use a self-signed cert but it would require disabling SSL verification on the MCP client, we DO NOT recommend you do that_. If you are hosting your MCP server on EC2 then you could generate an SSL cert using [no-ip](https://www.noip.com/) or [Let' Encrypt](https://letsencrypt.org/) or other similar services. Place the SSL cert and private key files in `/etc/ssl/certs` and `/etc/ssl/privatekey` folders respectively on your EC2 machine.

1. Install `nginx` on your EC2 machine using the following commands.

    ```{.bashrc}
    sudo apt-get install nginx
    sudo nginx -t
    sudo systemctl reload nginx
    ```

1. Get the hostname for your EC2 instance, this would be needed for configuring the `nginx` reverse proxy.

    ```{.bashrc}
    TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/public-hostname
    ```

1. Copy the following content into a new file `/etc/nginx/conf.d/ec2.conf`. Replace `YOUR_EC2_HOSTNAME`, `/etc/ssl/certs/cert.pem` and `/etc/ssl/privatekey/privkey.pem` with values appropriate for your setup.

   ```{.bashrc}
   server {
    listen 80;
    server_name YOUR_EC2_HOSTNAME;

    # Optional: Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        server_name YOUR_EC2_HOSTNAME;

        # Self-signed certificate paths
        ssl_certificate     /etc/ssl/certs/cert.pem;
        ssl_certificate_key /etc/ssl/privatekey/privkey.pem; 

        # Optional: Good practice
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        location / {
            # Reverse proxy to your local app (e.g., port 8000)
            proxy_pass http://127.0.0.1:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }

   ```

1. Restart `nginx`.

    ```{.bashrc}
    sudo systemctl start nginx
    ```

1. Start your MCP server as usual as described in the [remote setup](#remote-setup) section.

1. Your MCP server is now accessible over HTTPS as `https://your-mcp-server-domain-name.com/sse` to your MCP client.
