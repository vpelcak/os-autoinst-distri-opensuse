 # SUSE's openQA tests
 #
 # Copyright © 2009-2013 Bernhard M. Wiedemann
 # Copyright © 2012-2019 SUSE LLC
 #
 # Copying and distribution of this file, with or without modification,
 # are permitted in any medium without royalty provided the copyright
 # notice and this notice are preserved.  This file is offered as-is,
 # without any warranty.
 
 # Summary: yast lan in cli, creates, edits and deletes device and lists and
 # shows details of the device
 # Maintainer: Vit Pelcak <vpelcak@suse.cz>

use base 'consoletest';
use strict;
use testapi;
sub run {
    select_console 'root-console';
    assert_script_run 'zypper -n in yast2-network';
    assert_script_run 'yast lan add name=vlan50 ethdevice=eth0';
    assert_script_run 'yast lan list';
    assert_script_run 'yast lan show id=1';
    assert_script_run 'yast lan edit id=1 bootproto=dhcp';
    assert_script_run 'yast lan show id=1';
    assert_script_run 'yast lan delete id=1';
    assert_script_run 'yast lan list';
}
sub post_run_hook {}
1;
