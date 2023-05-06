<div align="center">

<h1>Course design of software testing</h1>

<span>English</span> | <a href="./README-ZH.md">中文文档</a> | <a href="./setup/README.md">Setup</a>

</div>

## Requirements

1. Monitor the regular indicators of linux kernel based on `ebpf`.

2. Need to collect relevant research materials in this field (word/ppt/pdf, etc.)

3. Implement several common monitoring indicators, including at least the following: `process tcp setup time` `number of network retransmissions` `tcprtt` `biolatency`

4. Implement front-end display of monitoring indicators, with the ability to select the displayed monitoring indicators and the observation time period.

5. The monitoring indicators are configurable, which allows both existing indicators to be specified and new indicators to be added via the configuration file.

6. The monitoring data supports customization to the specified database, such as `Promethus` `Elasticsearch` and so on.

7. The monitoring `agent` is required to have a simple deployment configuration, consisting of one executable file and one configuration file.
