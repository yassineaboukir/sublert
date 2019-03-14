#!/usr/bin/python

# Slack webhooks for notifications
posting_webhook = "https://hooks.slack.com/services/<secret>"
errorlogging_webhook = "https://hooks.slack.com/services/<secret>"
slack_sleep_enabled = True  # bypass Slack rate limit when using free workplace, remove this line if you've pro subscription

# crtsh postgres credentials
DB_HOST = 'crt.sh'
DB_NAME = 'certwatch'
DB_USER = 'guest'
DB_PASSWORD = ''
