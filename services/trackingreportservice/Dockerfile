FROM ubuntu:24.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-php8.3 \
    php8.3 \
    php8.3-cli \
    php8.3-mysql \
    php8.3-mbstring \
    php8.3-xml \
    php8.3-gd \
    php8.3-curl \
    php8.3-zip \
    php8.3-bcmath \
    php8.3-ctype \
    git \
    curl \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN a2enmod rewrite \
    && a2dissite 000-default
COPY docker/apache-site.conf /etc/apache2/sites-available/trackingreportservice.conf
RUN a2ensite trackingreportservice \
    && echo 'ServerName localhost' >> /etc/apache2/apache2.conf

RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log \
    && ln -sf /proc/self/fd/2 /var/log/apache2/error.log \
    && ln -sf /proc/self/fd/2 /var/log/apache2/other_vhosts_access.log

WORKDIR /var/www

COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

COPY . /var/www

RUN mkdir -p /var/www/var/cache /var/www/var/log /var/www/var/reports /var/www/var/reports/exports \
    && chown -R www-data:www-data /var/www

RUN APP_ENV=prod APP_SECRET=buildsecret php bin/console cache:warmup --env=prod --no-debug \
    && chown -R www-data:www-data /var/www/var

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]
