# SUSE's openQA tests
#
# Copyright © 2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: Advanced test cases for wicked
# Test 6 : Create a IPIP interface from Wicked XML files
# Maintainer: Anton Smorodskyi <asmorodskyi@suse.com>
#             Jose Lausuch <jalausuch@suse.com>
#             Clemens Famulla-Conrad <cfamullaconrad@suse.de>

use base 'wickedbase';
use strict;
use testapi;

sub run {
    my ($self) = @_;
    my $config = '/etc/wicked/ifconfig/ipip.xml';
    record_info('Info', 'Create a IPIP interface from Wicked XML files');
    $self->get_from_data('wicked/xml/ipip.xml', $config);
    $self->setup_tunnel($config, 'tunl1');
    my $res = $self->get_test_result('tunl1');
    die if ($res eq 'FAILED');
}

sub test_flags {
    return {always_rollback => 1, wicked_need_sync => 1};
}

1;