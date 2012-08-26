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
import argparse


class EmailException(Exception):
    def __init(self, error_no, raw_email, email, detail):
        self.error_no = error_no
        self.raw_email = raw_email
        self.email = email
        self.detail = detail


def extract_id_from_msg(raw_msg, spamReportHeaderKey):
    msg = email.message_from_string("\n".join(raw_msg[1]))

    if not msg.is_multipart():
        raise EmailException(1, raw_msg, msg, "Message is not multipart!")
    
    for part_idx, part in enumerate(msg.walk()):
        # Extract mailscanner id of this part from the headers
        mailscanner_id_match = re.search(r"MailScanner-ID:.([-\w]+)\n", 
                                         part.as_string(), re.IGNORECASE | re.MULTILINE | re.VERBOSE)
        
        # If this part is from the fowarder
        if part_idx==0:
            sender = part['From']
            print "  Reported by %s" % sender
            if mailscanner_id_match:
                print "  ID of reporter msg: %s" % mailscanner_id_match.group(1)
            
            # TODO CHECK THAT USER IS ALLOWED TO REPORT
            if not "ALL_TRUSTED" in part[spamReportHeaderKey]:
                raise EmailException(2, raw_msg, msg, "Message %d is not trusted!" % msg_idx)
            
        # If this is the fowarded ham/spam
        elif part_idx==2:
            if not mailscanner_id_match:
                raise EmailException(3, raw_msg, msg, "Can't match")
                
            print "  --- Spam message ---"
            mailscanner_id = mailscanner_id_match.group(1)
            print "  ID: %s" % mailscanner_id
            print "    %s -> %s" % (part['From'], part['To'])
        
            return ([mailscanner_id, part])




def load_msgs_from_pop(config, eraseFromServer=True):
    spamReportHeaderKey = config.get('AUTH REPORTERS', 'spamReportHeaderKey')
    for report_type in ['spam', 'ham']:
        # Connect to the pop3 server
        pop3 = poplib.POP3(config.get('POP', 'host'))
        pop3.user(config.get('POP', 'user_%s' % report_type))
        pop3.pass_(config.get('POP', 'pass_%s' % report_type))

        # Iterate over all messages
        num_msg, mailbox_size = pop3.stat()
        for msg_idx in xrange(num_msg):
            print "\n=== Loading message - %s ===" % datetime.datetime.now()
            # Fetch the message and parse it into an email object
            raw_msg = pop3.retr(msg_idx+1)
            try:
                msg_id, msg_contents = extract_id_from_msg(raw_msg, spamReportHeaderKey)
                yield report_type, msg_id, msg_contents
            except Exception as e:
                print e
                continue

            # We've processed the message so delete it
            if eraseFromServer:
                pop3.dele(msg_idx+1)
        
        pop3.quit()


def train_on_id(report_type, mailscanner_id, quarantine_folder):
    path_to_message = subprocess.check_output(['find', '%s' % quarantine_folder, '-name', '%s' % (mailscanner_id)]).strip()
    if not os.path.exists(path_to_message): raise ValueError("For id:'%s', found path '%s' but it does not exist." % (mailscanner_id, path_to_message))
    print "   Path to message: %s" % path_to_message
    print subprocess.check_output(['sa-learn', '--no-sync', '--%s' % report_type, '%s' % path_to_message])

    # and print status: sa-learn --dump magic




def train_sa(config_file='pysalearn.cnf', debug=False):

    print "Started Spamassassin automatic trainer"
    print "------"
    
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    quarantine_folder = config.get('SPAMASSASSIN', 'quarantine_folder')

    while True:    
        trained_cnt = {'spam':0, 'ham':0}
        for report_type, msg_id, msg_contents in load_msgs_from_pop(config, not debug):
            if debug:
                print "  Would train on %s (%s)" % (msg_id, report_type)
                continue
            print "  Training on %s (%s)" % (msg_id, report_type)
            try:
                train_on_id(report_type, msg_id, quarantine_folder)
                trained_cnt[report_type]+=1
            except ValueError as e:
                print e

        if any((cnt>0 for cnt in trained_cnt.values())):
            print "Trained on %d spams, %d hams. Synching db..." % (trained_cnt['spam'], trained_cnt['ham'])
            print subprocess.check_output(['sa-learn', '--sync'])
            print "\n"

        # Sleep for 5 minutes if not in debug mode
        if debug: return
        sys.stdout.write("\r Last check at %s. Sleeping for 5 minutes..." % datetime.datetime.now())
        time.sleep(5*60)



parser = argparse.ArgumentParser(description='pysalearn')
parser.add_argument("--debug", help="Don't do any training. Just load messages and extract ids", action="store_true")

args = parser.parse_args()

train_sa(debug=args.debug)

