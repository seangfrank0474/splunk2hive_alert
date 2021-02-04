# splunk2hive_alert event settings

action.splunk2hive_alert = [0|1]
* Enable thehive_create_case notification

action.splunk2hive_alert.param.title = <string>
* Case Title to use in TheHive.
* (required)

action.splunk2hive_alert.param.description = <string>
* The description of the case to send to TheHive.
* (required)

action.splunk2hive_alert.param.severity = [0|1|2|3]
* The severity of the new case. 1 = low, 2 = medium, 3 = high
* Default is "1" (low)
* (optional)

action.splunk2hive_alert.param.owner = <string>
* Case owner. Defaults to user name that creates the case.
* (optional)

action.splunk2hive_alert.param.tlp = [-1|0|1|2|3]
* Traffic Light Protocol for this case. 0 = White, 1 = Green, 2 = Amber, 3 = Red
* TLP affects releasability of information. Some analyzers will not be available on higher TLP settings.
* Defaults to "2" (Amber)
* (optional)

action.splunk2hive_alert.param.tags = <string>
* The tags to put on the case. Use a single, comma-separated string (ex. "badIP,trojan").
* (optional)
