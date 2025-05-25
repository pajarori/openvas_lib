#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This file contains OMPUniversal implementation
"""

from openvas_lib import *
from openvas_lib.common import *

try:
	from xml.etree import cElementTree as etree
except ImportError:
	from xml.etree import ElementTree as etree

__license__ = """
Copyright 2018 - Golismero project

Redistribution and use in source and binary forms, with or without modification
, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
"""

__all__ = ["OMPUniversal"]


# ------------------------------------------------------------------------------
#
# OMP implementation
#
# ------------------------------------------------------------------------------
class OMPUniversal(OMP):
	"""
	Internal manager for OpenVAS low level operations.

	..note:
		This class is based in code from the original OpenVAS plugin:

		https://pypi.python.org/pypi/OpenVAS.omplib

	..warning:
		This code is only compatible with OMP 4.0.
	"""

	# ----------------------------------------------------------------------
	def __init__(self, omp_manager):
		"""
		Constructor.

		:param omp_manager: _OMPManager object.
		:type omp_manager: ConnectionManager
		"""
		# Call to super
		super(OMPUniversal, self).__init__(omp_manager)

	# ----------------------------------------------------------------------
	#
	# PUBLIC METHODS
	#
	# ----------------------------------------------------------------------
	# ----------------------------------------------------------------------
	#
	# METHODS FOR ROLES
	#
	# ----------------------------------------------------------------------
	def get_roles(self):
		"""
		Get roles in OpenVAS.

		:return: a dict with the format: {role_name: role_ID}
		"""
		# self._manager.get_roles()
		elems = etree.fromstring(self._manager.get_roles())

		m_return = {}

		for x in elems.findall("role"):
			m_return[x.find("name").text.lower()] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR USER
	#
	# ----------------------------------------------------------------------

	def create_user(self, name, password, role, allow_hosts='0', hosts=[], allow_ifaces='0', ifaces=[]):
		"""
		Creates a new user in OpenVAS.

		:param name: The name of the user to be created.
		:type name: str

		:param password: The password for the user.
		:type password: str

		:param role: A role of the user. If the role not exists in the roles dict then use a user role ID.
		:type role: str

		:param allow_hosts: User access rules: 0 allow all and deny list of hosts (default), 1 deny all and allow list of hosts.
		:type allow_hosts: int

		:param hosts: User access rules: a textual list of hosts (host access).
		:type hosts: list

		:param allow_ifaces: User access rules: 0 allow all and deny list of ifaces (default), 1 deny all and allow list of ifaces.
		:type allow_ifaces: int

		:param ifaces: User access rules: a textual list of ifaces (interfaces access).
		:type ifaces: list

		:return: the ID of the created user (UUID).
		:rtype: str

		"""

		roles = self.get_roles()
		role_id=roles.get(role, 'user')

		roles = self.get_roles()
		role_id=roles.get(role, 'user')

		return etree.fromstring(self._manager.create_user(
			name=name, 
			password=password, 
			role_ids=[role_id], 
			hosts_allow=allow_hosts, 
			hosts=hosts)
		).get("id")

	# ----------------------------------------------------------------------

	def delete_user(self, user_id='', name=''):
		"""
		Delete a user in OpenVAS.

		:param user_id: The ID of the user to be deleted. Overrides name.
		:type user_id: str

		:param name: The name of the user to be deleted.
		:type name: str

		"""

		if user_id:
			self._manager.delete_user(user_id=user_id)
		elif name:
			self._manager.delete_user(name=name)

	# ----------------------------------------------------------------------

	def modify_user(self, user_id, new_name='', password='', role_id='', allow_hosts=None, hosts=[], allow_ifaces=None, ifaces=[]):
		"""
		Modify a user in OpenVAS.

		:param user_id: The ID of the user to be modified.
		:type user_id: str

		:param new_name: The new name for the user.
		:type new_name: str

		:param password: The password for the user.
		:type password: str

		:param role_id: A role of the user.
		:type role_id: str

		:param allow_hosts: User access rules: 0 allow all and deny list of hosts (default), 1 deny all and allow list of hosts.
		:type allow_hosts: int

		:param hosts: User access rules: a textual list of hosts (host access).
		:type hosts: list of string

		:param allow_ifaces: User access rules: 0 allow all and deny list of ifaces (default), 1 deny all and allow list of ifaces.
		:type allow_ifaces: int

		:param ifaces: User access rules: a textual list of ifaces (interfaces access).
		:type ifaces: list of string

		"""

		request = """<modify_user user_id="%s">""" % user_id

		if new_name:
			request += """<new_name>%s</new_name>""" % new_name

		if password:
			request += """<password>%s</password>""" % password

		if role_id:
			request += """<role id="%s"/>""" % role_id

		###HOSTS###
		if not hosts:
			allow_hosts = '0'
		if allow_hosts:
			request += """<hosts allow="%s">""" % allow_hosts
		else:
			request += """<hosts>"""

		if hosts:
			request += """%s""" % str(",".join(hosts))
		request += """</hosts>"""

		###IFACES###
		if not hosts:
			allow_ifaces = '0'
		if allow_ifaces:
			request += """<ifaces allow="%s">""" % allow_ifaces
		else:
			request += """<ifaces>"""

		if ifaces:
			request += """%s""" % str(",".join(ifaces))
		request += """</ifaces>"""

		request += """</modify_user>"""

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def get_users(self, user_id=None):
		"""
		Get a user in OpenVAS.

		:param user_id: ID of single user to get.
		:type user_id: str

		:return: The user.
		:rtype: str

		"""

		if not user_id:
			elems = etree.fromstring(self._manager.get_users())
			m_return = {}

			for x in elems.findall("user"):
				m_return[x.find("name").text.lower()] = x.get("id")

			return m_return
		else:
			if not isinstance(user_id, str):
				raise TypeError("Expected string, got %r instead" % type(user_id))

			return etree.fromstring(self._manager.get_user(user_id)).find('.//user[@id="%s"]' % user_id)

	# ----------------------------------------------------------------------
	#
	# METHODS FOR PORT_LISTS
	#
	# ----------------------------------------------------------------------
	def create_port_list(self, name, port_range, comment=""):
		"""
		Creates a port list in OpenVAS.

		:param name: name to the port list
		:type name: str

		:param port_range: Port ranges. Should be a string of the form "T:22-80,U:53,88,1337"
		:type port_range: str

		:param comment: comment to add to the port list
		:type comment: str

		:return: the ID of the created target.
		:rtype: str

		:raises: ClientError, ServerError TODO
		"""

		return etree.fromstring(self._manager.create_port_list(name, port_range, comment)).get("id")

	# ----------------------------------------------------------------------

	def delete_port_list(self, port_list_id):
		"""
		Delete a user in OpenVAS.

		:param port_list_id: The ID of the port list to be deleted
		:type port_list_id: str

		:param name: The name of the user to be deleted.
		:type name: str

		"""

		self._manager.delete_port_list(port_list_id)

	# ----------------------------------------------------------------------

	def get_scanners(self, scanner_id=None):
		"""
		Get scanners in OpenVAS.

		If scanner_id is provided, only get the scanner associated to this id.

		:param scanner_id: scanner id to get
		:type scanner_id: str

		:return: `ElementTree`

		:raises: ClientError, ServerError
		"""
		# if scanner_id:
		# 	return etree.fromstring(self._manager.get_scanners(filter_id=scanner_id))
		# else:
		# 	return etree.fromstring(self._manager.get_scanners())

		m_return = {}

		if not scanner_id:
			elems = etree.fromstring(self._manager.get_scanners())

			for x in elems.findall("scanner"):
				m_return[x.find("name").text.lower()] = x.get("id")
		else:
			if not isinstance(scanner_id, str):
				raise TypeError("Expected string, got %r instead" % type(scanner_id))

			scanner = etree.fromstring(self._manager.get_scanners(filter_id=scanner_id)).find('.//scanner[@id="%s"]' % scanner_id)
			m_return[scanner.find("name").text.lower()] = scanner.get("id")
		
		return m_return


	def get_port_lists(self, port_list_id=None):
		"""
		Get a user in OpenVAS.

		:param port_list_id: ID of single port list to get.
		:type port_list_id: str

		:return: port list dict
		:rtype: str

		"""
		m_return = {}

		if not port_list_id:
			elems = etree.fromstring(self._manager.get_port_lists(details='1'))

			for x in elems.findall("port_list"):
				port_ranges = []
				for r in x.findall("port_ranges/port_range"):
					type = r.find('type').text
					start = r.find('start').text
					end = r.find('end').text
					port_ranges.append("%s:%s-%s" % (type, start, end))

				m_return[x.find("name").text.lower()] = {'id' : x.get("id"), 'port_ranges': port_ranges}
		else:
			if not isinstance(port_list_id, str):
				raise TypeError("Expected string, got %r instead" % type(port_list_id))

			port_list = etree.fromstring(self._manager.get_port_lists(filter_id=port_list_id, details='1')).find('.//port_list[@id="%s"]' % port_list_id)
			port_ranges = []
			for r in port_list.findall("port_ranges/port_range"):
				type = r.find('type').text
				start = r.find('start').text
				end = r.find('end').text
				port_ranges.append("%s:%s-%s" % (type, start, end))

			m_return[port_list.find("name").text.lower()] = {'id' : port_list.get("id"), 'port_ranges': port_ranges}

		return m_return
	# ----------------------------------------------------------------------

	# ----------------------------------------------------------------------
	#
	# METHODS FOR OTHER
	#
	# ----------------------------------------------------------------------
	def create_schedule(self, name, hour, minute, month, day, year, period=None, duration=None,timezone="UTC"):
		"""
		Creates a schedule in the OpenVAS server.

		:param name: name to the schedule
		:type name: str

		:param hour: hour at which to start the schedule, 0 to 23
		:type hour: str

		:param minute: minute at which to start the schedule, 0 to 59
		:type minute: str

		:param month: month at which to start the schedule, 1-12
		:type month: str

		:param year: year at which to start the schedule
		:type year: str

		:param timezone: The timezone the schedule will follow. The format of a timezone is the same as that of the TZ environment variable on GNU/Linux systems
		:type timezone: str

		:param period:How often the Manager will repeat the scheduled task. Assumed unit of days
		:type period: str

		:param duration: How long the Manager will run the scheduled task for. Assumed unit of hours
		:type period: str

		:return: the ID of the created schedule.
		:rtype: str

		:raises: ClientError, ServerError
		"""
		
		from datetime import datetime
		from icalendar import Calendar, Event


		calendar = Calendar()
		calendar.add('prodid', '-//Golismero//OpenVAS//EN')
		calendar.add('version', '2.0')

		event = Event()
		event.add('summary', name)
		event.add('dtstart', datetime(int(year), int(month), int(day), int(hour), int(minute)))
		event.add('dtstamp', datetime.now())
		event.add('dtend', datetime(int(year), int(month), int(day), int(hour) + 1, int(minute)))
		event.add('rrule', {
			'freq': 'DAILY',
			'interval': 1,
			'count': 1
		})
		calendar.add_component(event)

		return etree.fromstring(self._manager.create_schedule(
			name=name,
			icalendar=calendar.to_ical(),
			timezone=timezone,
		)).get("id")

	# ----------------------------------------------------------------------

	def get_schedules(self, schedule_id=None, tasks="1"):
		"""
		Get schedules in the server.

		If schedule_id is provided, only get the schedule associated to this id.

		:param schedule_id: schedule id to get
		:type schedule_id: str

		:return: `ElementTree`

		:raises: ClientError, ServerError
		"""
		if schedule_id:
			return etree.fromstring(self._manager.get_schedules(filter_id=schedule_id, tasks=tasks))
		else:
			return etree.fromstring(self._manager.get_schedules(tasks=tasks))

	# ----------------------------------------------------------------------

	def get_tasks_schedules(self, schedule_id):
		"""
		Get tasks that have schedule in the server.

		:return: list of dicts [{'task_id':task_ID, 'schedule_id':schedule_ID}]

		:raises: ClientError, ServerError
		"""

		results = []

		schedules = self.get_schedules(schedule_id).findall('schedule')

		for s in schedules:
			schedule_id = s.get('id')
			tasks = s.findall('tasks/task')

			for task in tasks:
				results.append({'task_id':task.get('id'), 'schedule_id':schedule_id})

		return results
	# ----------------------------------------------------------------------

	def delete_schedule(self, schedule_id, ultimate=False):
		"""
		Delete a schedule.

		:param schedule_id: schedule_id
		:type schedule_id: str

		:param ultimate: remove or not from trashcan
		:type ultimate: bool

		:raises: AuditNotFoundError, ServerError
		"""

		etree.fromstring(self._manager.delete_schedule(schedule_id=schedule_id, ultimate=ultimate))

	# ----------------------------------------------------------------------
	# ----------------------------------------------------------------------
	#
	# METHODS FOR CONFIG
	#
	# ----------------------------------------------------------------------
	def get_configs(self, config_id=None):
		"""
		Get information about the configs in the server.

		If name param is provided, only get the config associated to this name.

		:param config_id: config id to get
		:type config_id: str

		:return: `ElementTree`

		:raises: ClientError, ServerError
		"""
		# Recover all config from OpenVAS
		if config_id:
			return etree.fromstring(self._manager.get_scan_configs(filter_id=config_id, details='1')).find('.//config[@id="%s"]' % config_id)
		else:
			return etree.fromstring(self._manager.get_scan_configs(details='1'))
		
	# ----------------------------------------------------------------------
	def get_configs_ids(self, name=None):
		"""
		Get information about the configured profiles (configs)in the server.

		If name param is provided, only get the ID associated to this name.

		:param name: config name to get
		:type name: str

		:return: a dict with the format: {config_name: config_ID}

		:raises: ClientError, ServerError
		"""
		m_return = {}

		for x in self.get_configs().findall("config"):
			m_return[x.find("name").text] = x.get("id")

		if name:
			return {name: m_return[name]}
		else:
			return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR TARGET
	#
	# ----------------------------------------------------------------------

	def create_target(self, name, hosts, comment="", port_list="", alive_test=""):
		"""
		Creates a target in OpenVAS.

		:param name: name to the target
		:type name: str

		:param hosts: target list. Can be only one target or a list of targets
		:type hosts: str | list(str)

		:param comment: comment to add to task
		:type comment: str

		:param port_list: Port List ID to use for the target
		:type port_list: str

		:param alive_test: Alive Test to check if a target is reachable
		:type alive_test: str

		:return: the ID of the created target.
		:rtype: str

		:raises: ClientError, ServerError
		"""

		if not port_list:
			port_list = self.get_port_lists().get("all iana assigned tcp").get('id')

		from collections.abc import Iterable
		if isinstance(hosts, str):
			m_targets = hosts
		elif isinstance(hosts, Iterable):
			m_targets = str(",".join(hosts))

		return etree.fromstring(self._manager.create_target(
			name=name,
			hosts=m_targets,
			comment=comment,
			port_list_id=port_list,
			alive_test=alive_test
		))

	# ----------------------------------------------------------------------

	def delete_target(self, target_id):
		"""
		Delete a target in OpenVAS server.

		:param target_id: target id
		:type target_id: str

		:raises: ClientError, ServerError
		"""

		self._manager.delete_target(target_id=target_id)

	# ----------------------------------------------------------------------

	def get_targets(self, target_id=None):
		"""
		Get information about the targets in the server.

		If name param is provided, only get the target associated to this name.

		:param target_id: target id to get
		:type target_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		m_return = {}
		# Recover all config from OpenVAS
		if target_id:
			targets = etree.fromstring(self._manager.get_targets(filter_id=target_id, details='1'))
		else:
			targets = etree.fromstring(self._manager.get_targets(details='1'))

		for x in targets.findall("target"):
			m_return[x.find("name").text] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------

	def get_targets_ids(self, name=None):
		"""
		Get IDs of targets of the server.

		If name param is provided, only get the ID associated to this name.

		:param name: target name to get
		:type name: str

		:return: a dict with the format: {target_name: target_ID}

		:raises: ClientError, ServerError
		"""

		m_return = self.get_targets()

		if name:
			return m_return.get(name)
		else:
			return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR TASK
	#
	# ----------------------------------------------------------------------

	def create_task(self, name, target, config=None, schedule=None, comment="", max_checks=None, max_hosts=None):
		"""
		Creates a task in OpenVAS.

		:param name: name to the task
		:type name: str

		:param target: target to scan
		:type target: str

		:param config: config (profile) name
		:type config: str

		:param schedule: schedule ID to use.
		:type schedule: str

		:param comment: comment to add to task
		:type comment: str

		:param max_hosts: Maximum concurrently scanned hosts.
		:type max_hosts: int

		:param max_checks: Maximum concurrently executed NVTs per host.
		:type max_checks: int

		:return: the ID of the task created.
		:rtype: str

		:raises: ClientError, ServerError
		"""

		if not config:
			config = "Full and fast"

		return etree.fromstring(self._manager.create_task(
			name=name,
			target_id=target,
			config_id=config,
			schedule_id=schedule,
			comment=comment,
			preferences={
				'max_checks': max_checks,
				'max_hosts': max_hosts
			}
		)).get("id")

	# ----------------------------------------------------------------------

	def start_task(self, task_id):
		"""
		Start a task.

		:param task_id: ID of task to start.
		:type task_id: str

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		m_response = etree.fromstring(self._manager.start_task(task_id=task_id))

		return m_response

	# ----------------------------------------------------------------------

	def delete_task(self, task_id, ultimate=False):
		"""
		Delete a task in OpenVAS server.

		:param task_id: task id
		:type task_id: str

		:param ultimate: remove or not from trashcan
		:type ultimate: bool

		:raises: AuditNotFoundError, ServerError
		"""

		try:
			etree.fromstring(self._manager.delete_task(task_id=task_id, ultimate=ultimate))
		except ClientError:
			raise AuditNotFoundError()

	# ----------------------------------------------------------------------

	def stop_task(self, task_id):
		"""
		Stops a task in OpenVAS server.

		:param task_id: task id
		:type task_id: str

		:raises: ServerError, AuditNotFoundError
		"""
		
		etree.fromstring(self._manager.stop_task(task_id=task_id))

	# ----------------------------------------------------------------------

	def _get_tasks(self, task_id=None):
		"""
		Get information about the configured profiles in the server.

		If name param is provided, only get the task associated to this name.

		:param task_id: task id to get
		:type task_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		# Recover all task from OpenVAS

		if task_id:
			return etree.fromstring(self._manager.get_tasks(filter_id=task_id, details='1')).find('.//task[@id="%s"]' % task_id)
		else:
			return etree.fromstring(self._manager.get_tasks(details='1')).find('.//tasks')


	def get_tasks(self, task_id=None):
		"""
		Get information about the configured profiles in the server.

		If name param is provided, only get the task associated to this name.

		:param task_id: task id to get
		:type task_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		# Recover all task from OpenVAS

		m_return = {}

		if task_id:
			tasks = self._get_tasks(task_id).find('.//task[@id="%s"]' % task_id)
		else:
			tasks = self._get_tasks()

		for x in tasks.findall("task"):
			m_return[x.find("name").text] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------

	def get_tasks_ids(self, name=None):
		"""
		Get IDs of tasks of the server.

		If name param is provided, only get the ID associated to this name.

		:param name: task name to get
		:type name: str

		:return: a dict with the format: {task_name: task_ID}

		:raises: ClientError, ServerError
		"""
		m_return = self.get_tasks()

		if name:
			return m_return.get(name)
		else:
			return m_return

	# ----------------------------------------------------------------------

	def get_tasks_progress(self, task_id):
		"""
		Get the progress of the task.

		:param task_id: ID of the task
		:type task_id: str

		:return: a float number between 0-100
		:rtype: float

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		m_sum_progress = 0.0  # Partial progress
		m_progress_len = 0.0  # All of tasks

		# Get status with xpath
		tasks = self._get_tasks()
		status = tasks.find('.//task[@id="%s"]/status' % task_id)

		if status is None:
			raise ServerError("Task not found")

		if status.text in ("Running", "Pause Requested", "Paused"):
			h = tasks.findall('.//task[@id="%s"]/progress/host_progress/host' % task_id)

			if h is not None:
				m_progress_len += float(len(h))
				m_sum_progress += sum([float(x.tail) for x in h])

		elif status.text in ("Delete Requested", "Done", "Stop Requested", "Stopped", "Internal Error"):
			return 100.0  # Task finished

		try:
			return m_sum_progress / m_progress_len
		except ZeroDivisionError:
			return 0.0

	# ----------------------------------------------------------------------

	def get_tasks_detail(self, task_id):
		"""
		Get the xml of the details associated to the task ID.

		:param task_id: ID of task.
		:type task_id: str

		:return: xml object
		:rtype: `ElementTree`

		:raises: ClientError, ServerError
		"""

		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		try:
			m_response = self._manager.get_tasks(filter_id=task_id, details='1')
		except ServerError as e:
			raise VulnscanServerError("Can't get the detail for the task %s. Error: %s" % (task_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def get_task_status(self, task_id):
		"""
		Get task status

		:param task_id: ID of task to check.
		:type task_id: str

		:return: status of a task
		:rtype: str

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		status = self._get_tasks().find('.//task[@id="%s"]/status' % task_id)

		if status is None:
			raise ServerError("Task not found")

		return status.text

	# ----------------------------------------------------------------------

	def is_task_running(self, task_id):
		"""
		Return true if task is running

		:param task_id: ID of task to check.
		:type task_id: str

		:return: bool
		:rtype: bool

		:raises: ClientError, ServerError
		"""

		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		status = self.get_task_status(task_id)

		if status is None:
			raise ServerError("Task not found")

		return status in ("Running", "Requested")

	# ----------------------------------------------------------------------

	def get_tasks_ids_by_status(self, status="Done"):
		"""
		Get IDs of tasks of the server depending of their status.

		Allowed status are: "Done", "Paused", "Running", "Stopped".

		If name param is provided, only get the ID associated to this name.

		:param status: get task with this status
		:type status: str - ("Done" |"Paused" | "Running" | "Stopped".)

		:return: a dict with the format: {task_name: task_ID}

		:raises: ClientError, ServerError
		"""
		if status not in ("Done", "Paused", "Running", "Stopped"):
			raise ValueError("Requested status are not allowed")

		m_task_ids = {}

		for x in self._get_tasks().findall("task"):
			if x.find("status").text == status:
				m_task_ids[x.find("name").text] = x.attrib["id"]

		return m_task_ids

	# ----------------------------------------------------------------------

	def get_results(self, task_id=None):
		"""
		Get the results associated to the scan ID.

		:param task_id: ID of scan to get. All if not provided
		:type task_id: str

		:return: xml object
		:rtype: `ElementTree`

		:raises: ClientError, ServerError
		"""

		if task_id:
			return etree.fromstring(self._manager.get_results(task_id=task_id, xml_result=True))
		else:
			return etree.fromstring(self._manager.get_results(xml_result=True))

	# ----------------------------------------------------------------------
	#
	# METHODS FOR REPORT
	#
	# ----------------------------------------------------------------------

	def get_report_id(self, task_id):
		"""
		Get the report id associated to the task ID.

		:param task_id: ID of scan to get.
		:type task_id: str

		:return: ID of the report or None if the report isn't found
		:rtype: str

		"""
		m_response = self.get_tasks_detail(task_id)

		report = m_response.find('task').find('last_report')

		if not report:
			report = m_response.find('task').find("current_report")

		if report:
			return report[0].get("id")
		else:
			return

	# ----------------------------------------------------------------------

	def get_report_html(self, report_id):
		"""
		Get the html associated to the report ID.

		:param report_id: ID of report to get.
		:type report_id: str

		:return: base64 representing html page
		:rtype: base64

		"""
		if not isinstance(report_id, str):
			raise TypeError("Expected string, got %r instead" % type(report_id))

		m_response = ""

		try:
			m_response = etree.fromstring(self._manager.get_reports(filter_id=report_id))
		except ServerError as e:
			print("Can't get the HTML for the report %s. Error: %s" % (report_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def get_report_xml(self, report_id):
		"""
		Get the xml associated to the report ID.

		:param report_id: ID of report to get.
		:type report_id: str

		:return: xml object
		:rtype: `ElementTree`

		"""
		if not isinstance(report_id, str):
			raise TypeError("Expected string, got %r instead" % type(report_id))

		try:
			m_response = etree.fromstring(self._manager.get_reports(filter_id=report_id))
		except ServerError as e:
			print("Can't get the xml for the report %s. Error: %s" % (report_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def delete_report(self, report_id):
		"""
		Delete a report in OpenVAS server.

		:param report_id: report id
		:type report_id: str

		:raises: AuditNotFoundError, ServerError
		"""

		try:
			etree.fromstring(self._manager.delete_report(report_id=report_id))
		except ClientError:
			raise AuditNotFoundError()

	# ----------------------------------------------------------------------
	#
	# METHODS FOR SYNC
	#
	# ----------------------------------------------------------------------

	def sync_cert(self):
		"""
		Do the sync of cert.
		"""
		self._manager.make_xml_request('<sync_cert/>', xml_result=True)

	# ----------------------------------------------------------------------

	def sync_feed(self):
		"""
		Do the sync of feed.
		"""
		self._manager.make_xml_request('<sync_feed/>', xml_result=True)

	# ----------------------------------------------------------------------

	def sync_scap(self):
		"""
		Do the sync of scap.
		"""
		self._manager.make_xml_request('<sync_scap/>', xml_result=True)

	# ----------------------------------------------------------------------
