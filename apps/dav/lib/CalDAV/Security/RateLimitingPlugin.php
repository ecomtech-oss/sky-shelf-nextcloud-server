<?php

declare(strict_types=1);

/*
 * @copyright 2023 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author 2023 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace OCA\DAV\CalDAV\Security;


use OC\Security\RateLimiting\Exception\RateLimitExceededException;
use OC\Security\RateLimiting\Limiter;
use OCA\DAV\Connector\Sabre\Exception\TooManyRequests;
use OCP\IUserManager;
use Sabre\DAV;
use Sabre\DAV\ServerPlugin;
use function count;
use function explode;

class RateLimitingPlugin extends ServerPlugin {

	private Limiter $limiter;
	private IUserManager $userManager;
	private ?string $userId;

	public function __construct(Limiter $limiter,
		IUserManager $userManager,
		?string $userId) {
		$this->limiter = $limiter;
		$this->userManager = $userManager;
		$this->userId = $userId;
	}

	public function initialize(DAV\Server $server) {
		$server->on('beforeBind', [$this, 'beforeBind'], 1);
	}

	public function beforeBind($path) {
		$user = $this->userManager->get($this->userId);
		if ($user === null) {
			// We only care about authenticated users here
			return;
		}

		$pathParts = explode('/', $path);
		if (count($pathParts) === 3 && $pathParts[0] === 'calendars') {
			// Path looks like calendars/username/calendarname so a new calendar or subscription is created
			try {
				$this->limiter->registerUserRequest(
					'caldav-create-calendar',
					10,
					3600,
					$user
				);
			} catch (RateLimitExceededException $e) {
				throw new TooManyRequests('Too many calendars created', 0, $e);
			}
		} else if (count($pathParts) === 4 && $pathParts[0] === 'calendars') {
			// Path looks like calendars/username/calendarname/objecturi so a new calendar object is created
			try {
				$this->limiter->registerUserRequest(
					'caldav-create-calendar-object',
					50,
					5 * 60,
					$user
				);
			} catch (RateLimitExceededException $e) {
				throw new TooManyRequests('Too many calendar objects created', 0, $e);
			}
		}
	}

}
