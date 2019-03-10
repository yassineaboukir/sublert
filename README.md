                                       _____       __    __          __
                                      / ___/__  __/ /_  / /__  _____/ /_
                                      \__ \/ / / / __ \/ / _ \/ ___/ __/
                                     ___/ / /_/ / /_/ / /  __/ /  / /_
                                    /____/\__,_/_.___/_/\___/_/   \__/

                                Author: Yassine Aboukir (@yassineaboukir)
                                            Version: 1.0.0

## What's this about?
Sublert is a security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations and issued TLS/SSL certificate. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs DNS resolution to determine working subdomains.

## Requirements
- Virtual Private Server (VPS) running on Unix. (I personally use digitalOcean)
- Python 2.x or 3.x.
- Free Slack workplace.

## Installation & Configuration
Please refer to below article for a detailed technical explanation:
- https://medium.com/@yassineaboukir/automated-monitoring-of-subdomains-for-fun-and-profit-release-of-sublert-634cfc5d7708

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-u            | --url       | Adds a domain to monitor. E.g: yahoo.com.
-d            | --delete      | Domain to remove from the monitored list. E.g: yahoo.com.
-a            | --list       | Listing all monitored domains.
-t            | --threads       | Number of concurrent threads to use (Default: 20).
-r            | --resolve      | Perform DNS resolution.
-l            | --logging     | Enable Slack-based error logging.
-m            | --reset        | Reset everything.

## Is there a roadmap?
YES! The tool is now open sourced to be used by the community but contributions are valuable and highly appreciated. I have a number of items that I will be working on to polish the tool, among of which are:
- Use of a relational database instead of text files for storage.
- Extracting as much information as possible including: title, status code, screenshot and checking for potential subdomain takeovers.
- Integrate Telegram too for notification pushes.

## Feedback and issues?
If you have any feedback, anything that you want to see implemented or running into issues using Sublert, please feel free to file an issue on https://github.com/yassineaboukir/sublert/issues
