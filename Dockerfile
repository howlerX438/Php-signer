FROM php:8.2-apache

# Java install
RUN apt-get update && \
    apt-get install -y default-jre-headless && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# PHP extensions
RUN docker-php-ext-install fileinfo

# PHP upload size
RUN echo "upload_max_filesize=350M" > /usr/local/etc/php/conf.d/uploads.ini && \
    echo "post_max_size=350M" >> /usr/local/etc/php/conf.d/uploads.ini && \
    echo "max_execution_time=300" >> /usr/local/etc/php/conf.d/uploads.ini && \
    echo "memory_limit=512M" >> /usr/local/etc/php/conf.d/uploads.ini

# Apache rewrite
RUN a2enmod rewrite

WORKDIR /var/www/html
COPY . .

# Data folder
RUN mkdir -p data/signed && \
    chmod -R 777 data/ && \
    chmod 644 index.php

EXPOSE 80
CMD ["apache2-foreground"]