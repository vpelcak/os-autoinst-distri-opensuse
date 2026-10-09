# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run openQA-agnostic cpio functional tests
# Package: cpio
# Maintainer: Vit Pelcak <vpelcak@suse.com>

use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use package_utils 'install_package';
use agnosticTestRunner;

sub run {
    select_serial_terminal;
    # rpm -q exits non-zero (so script_run is truthy) when cpio is missing.
    # trup_apply applies the package before the version query below; the runner
    # later installs python3-pytest with trup_reboot, which may reboot anyway.
    install_package('cpio', trup_apply => 1) if script_run('rpm -q cpio');

    my $cpio_version = script_output(q(rpm -q --queryformat '%{VERSION}' cpio));
    record_info('cpio', "version $cpio_version");

    my $test = agnosticTestRunner->new({
            language => 'python',
            name => 'testCpio',
            domain => 'console',
        }
    );
    $test->setup()->run_test()->parse_results()->cleanup();
}

1;
