#/bin/bash


# This script creates tar archive with nextcloud files
# Usage:
# ./build-tar.sh

# Author: Aleksandr Lepesii <alepesiy@samokat.ru>
# License: GPLv3

DIRS=(
	3rdparty apps config core dist lib osc osc-provider resources themes updater
)
FILES=(
	composer.lock occ index.html *.json COPYING robots.txt console.php cron.php index.php public.php remote.php status.php version.php
)

# create archive
tar -cjvf nextcloud.tar.bz2 "${DIRS[@]}" "${FILES[@]}"
