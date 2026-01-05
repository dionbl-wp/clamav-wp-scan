# Clam AV Word Press Scan
## Quick Intro
This **plugin** will:
* allow Wordpress to scan (using Clam AV) any files that are uploaded using the Wordpress *Media Library* file import.
* restrict uploading to administrator/editor
* log the results and display in a widget

You will need to install ClamAV

This was tested on Ubuntu 24.04 // Wordpress 6.9

## WHAT THIS FILE (CalmAV-wp-scan) DOES
### Virus handling
* Infected files are deleted immediately
* An admin email is sent on infection
* There is a log of both clean & infected files scanned
* Scan time: is in Milliseconds in logfile, and Whole seconds (rounded) in dashboard
### Upload enforcement
This will *restrict* the roles that can upload
* To upload, you must have the role: administrator, editor
* All other roles are BLOCKED from uploading: everyone else (get a clear on-screen error)
### Automatic upload lockout
* If there are more than 4 infected files uploaded in a 30 minute window, then...
* Uploads are blocked for 3 hours
* Emergency override: you can stop lockout by creating the file **/wp-content/mu-plugins/force-allow-uploads.txt** You might for example want to do this so you can continue uploading. When this file is present there is a warning message in the security widgetyou can 
## Dashboard widgets
### Clam AV Plugin Scan Details
This widget displays:
* each file that is scanned is logged in the widget:
  - in the format: **filename [username] STATUS:Clean|Infected – scan time (in seconds)**
  - the lines are GREEN for clean, and RED for infected.
### ClamAV Security Events
## Installation
Simply copy the code to a **PHP** file in /wp-content/mu-plugins , eg:
> /var/www/html/wp-content/mu-plugins/clamav-wp-scan.php

Download the file here: https://github.com/dionbl-wp/clamav-wp-scan/blob/main/clamav-wp-scan.php

## Why use this
* No other MU-plugins required
* No external dependencies
* Emergency override file is intentionally simple and auditable
* Enforcement
* Observability (two widgets)
* Accountability (logging and widget)
* Failsafe override (for automatic upload blocking)
