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

namespace OCA\DAV\Tests\unit\CalDAV\Security;

use OCA\DAV\CalDAV\CalDavBackend;
use OCP\IAppConfig;
use Psr\Log\LoggerInterface;
use OC\Security\RateLimiting\Exception\RateLimitExceededException;
use OC\Security\RateLimiting\Limiter;
use OCA\DAV\CalDAV\Security\RateLimitingPlugin;
use OCA\DAV\Connector\Sabre\Exception\TooManyRequests;
use OCP\IUser;
use OCP\IUserManager;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class RateLimitingPluginTest extends TestCase {

	private Limiter|MockObject $limiter;
	private CalDavBackend|MockObject $caldavBackend;
	private IUserManager|MockObject $userManager;
	private LoggerInterface|MockObject $logger;
	private IAppConfig|MockObject $config;
	private string $userId = 'user123';
	private RateLimitingPlugin $plugin;

	protected function setUp(): void {
		parent::setUp();

		$this->limiter = $this->createMock(Limiter::class);
		$this->userManager = $this->createMock(IUserManager::class);
		$this->caldavBackend = $this->createMock(CalDavBackend::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->config = $this->createMock(IAppConfig::class);
		$this->plugin = new RateLimitingPlugin(
			$this->limiter,
			$this->userManager,
			$this->caldavBackend,
			$this->logger,
			$this->config,
			$this->userId,
		);
	}

	public function testNoUserObject(): void {
		$this->limiter->expects(self::never())
			->method('registerUserRequest');

		$this->plugin->beforeBind('calendars/foo/cal');
	}

	public function testUnrelated(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$this->limiter->expects(self::never())
			->method('registerUserRequest');

		$this->plugin->beforeBind('foo/bar');
	}

	public function testRegisterCalendarCreation(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$this->limiter->expects(self::once())
			->method('registerUserRequest')
			->with(
				'caldav-create-calendar',
				10,
				3600,
				$user,
			);
		$this->config->expects(self::once())
			->method('getValueInt')
			->with('dav', 'maximum_calendars', 30)
			->willReturn(12);

		$this->plugin->beforeBind('calendars/foo/cal');
	}

	public function testCalendarCreationRateLimitExceeded(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$this->limiter->expects(self::once())
			->method('registerUserRequest')
			->with(
				'caldav-create-calendar',
				10,
				3600,
				$user,
			)
			->willThrowException(new RateLimitExceededException());
		$this->expectException(TooManyRequests::class);

		$this->plugin->beforeBind('calendars/foo/cal');
	}

	public function testCalendarLimitReached(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$user->method('getUID')->willReturn('user123');
		$this->limiter->expects(self::once())
			->method('registerUserRequest')
			->with(
				'caldav-create-calendar',
				10,
				3600,
				$user,
			);
		$this->config->expects(self::once())
			->method('getValueInt')
			->with('dav', 'maximum_calendars', 30)
			->willReturn(12);
		$this->caldavBackend->expects(self::once())
			->method('getCalendarsForUserCount')
			->with('principals/users/user123')
			->willReturn(12);
		$this->expectException(TooManyRequests::class);

		$this->plugin->beforeBind('calendars/foo/cal');
	}

	public function testRegisterCalendarObjectCreation(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$this->limiter->expects(self::once())
			->method('registerUserRequest')
			->with(
				'caldav-create-calendar-object',
				50,
				5 * 60,
				$user,
			);

		$this->plugin->beforeBind('calendars/foo/cal/event1.ics');
	}

	public function testCalendarObjectCreationRateLimitExceeded(): void {
		$user = $this->createMock(IUser::class);
		$this->userManager->expects(self::once())
			->method('get')
			->with($this->userId)
			->willReturn($user);
		$this->limiter->expects(self::once())
			->method('registerUserRequest')
			->with(
				'caldav-create-calendar-object',
				50,
				5 * 60,
				$user,
			)
			->willThrowException(new RateLimitExceededException());
		$this->expectException(TooManyRequests::class);

		$this->plugin->beforeBind('calendars/foo/cal/event2.ics');
	}

}
