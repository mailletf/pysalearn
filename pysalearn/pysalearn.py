#!/usr/bin/env python
# 
# pysalearn
# Copyright (C) 2011-2012  Francois Maillet
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import ConfigParser
import poplib, email
import datetime
import time
import re
import os
import sys
import subprocess


def load_msgs_from_mailbox(host, user, passwd, spamReportHeaderKey):
    # Connect to the pop3 server
    pop3 = poplib.POP3(host)
    pop3.user(user)
    pop3.pass_(passwd)

    # Iterate over all messages
    num_msg, mailbox_size = pop3.stat()
    for msg_idx in xrange(num_msg):
        print "\n=== Loading message - %s ===" % datetime.datetime.now()
        # Fetch the message and parse it into an email object
        msg = email.message_from_string("\n".join(pop3.retr(msg_idx+1)[1]))

        if not msg.is_multipart():
            # TODO HANDLE
            print "Message %d is not multipart!" % msg_idx
            continue
        
        for part_idx, part in enumerate(msg.walk()):
            # Extract mailscanner id of this part from the headers
            mailscanner_id_match = re.search(r"MailScanner-ID:.([-\w]+)\n", part.as_string(), re.IGNORECASE | re.MULTILINE | re.VERBOSE)
            
            # If this part is from the fowarder
            if part_idx==0:
                sender = part['From']
                print "  Reported by %s" % sender
                if mailscanner_id_match:
                    print "  ID of reporter msg: %s" % mailscanner_id_match.group(1)
                
                # TODO CHECK THAT USER IS ALLOWED TO REPORT
                if not "ALL_TRUSTED" in part[spamReportHeaderKey]:
                    print "Message %d is not trusted!" % msg_idx
                    break
                    # TODO REJECT
                
            # If this is the fowarded ham/spam
            elif part_idx==2:
                if mailscanner_id_match:
                    print "  --- Spam message ---"
                    mailscanner_id = mailscanner_id_match.group(1)
                    print "  ID: %s" % mailscanner_id
                    print "    %s -> %s" % (part['From'], part['To'])
                
                    yield([mailscanner_id, part])
                    break
                
                else:
                    print "cant match!!"
                    # TODO

        # We've processed the message so delete it
        pop3.dele(msg_idx+1)
    
    pop3.quit()


def load_msgs(config):
    for report_type in ['spam', 'ham']:
        for msg_id, msg_contents in load_msgs_from_mailbox(config.get('POP', 'host'), config.get('POP', 'user_%s' % report_type),
                                                           config.get('POP', 'pass_%s' % report_type),
                                                           config.get('AUTH REPORTERS', 'spamReportHeaderKey')):
            yield report_type, msg_id, msg_contents


def train_on_message(report_type, mailscanner_id, quarantine_folder):
    path_to_message = subprocess.check_output(['find', '%s' % quarantine_folder, '-name', '%s' % (mailscanner_id)]).strip()
    if not os.path.exists(path_to_message): raise ValueError("For id:'%s', found path '%s' but it does not exist." % (mailscanner_id, path_to_message))
    print "   Path to message: %s" % path_to_message
    print subprocess.check_output(['sa-learn', '--no-sync', '--%s' % report_type, '%s' % path_to_message])

    # and print status: sa-learn --dump magic




def train_sa(config_file='pysalearn.cnf'):

    print "Started Spamassassin automatic trainer"
    print "------"
    
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    quarantine_folder = config.get('SPAMASSASSIN', 'quarantine_folder')

    while True:    
        trained_cnt = {'spam':0, 'ham':0}
        for report_type, msg_id, msg_contents in load_msgs(config):
            print "  Training on %s (%s)" % (msg_id, report_type)
            try:
                train_on_message(report_type, msg_id, quarantine_folder)
                trained_cnt[report_type]+=1
            except ValueError as e:
                print e

        if any((trained_cnt[report_type]>0 for report_type in ['spam', 'ham'])):
            print "Trained on %d spams, %d hams. Synching db..." % (trained_cnt['spam'], trained_cnt['ham'])
            print subprocess.check_output(['sa-learn', '--sync'])
            print "\n"

        # Sleep for 5 minutes
        sys.stdout.write("\r Last check at %s. Sleeping for 5 minutes..." % datetime.datetime.now())
        time.sleep(5*60)

train_sa()
