package pf::Switch::Cisco::Mist;
=head1 NAME

pf::Switch::Cisco::Mist - Object oriented module to parse SNMP traps and manage
Cisco Wireless Controllers (WLC) and Wireless Service Modules (WiSM)

=head1 STATUS

Developed and tested on firmware version 4.2.130 altought the new RADIUS RFC3576 support requires firmware v5 and later.

=over

=item Supports

=over

=item Deauthentication with RADIUS Disconnect (RFC3576)

=item Deauthentication with SNMP

=back

=back

=head1 BUGS AND LIMITATIONS

=over

=item Version specific issues

=over

=back

=back

=head1 SEE ALSO

=over

=back

=cut

use strict;
use warnings;

use Net::SNMP;
use Try::Tiny;

use base ('pf::Switch::Cisco');

use pf::constants;
use pf::config qw(
    $MAC
    $SSID
    $WEBAUTH_WIRELESS
);
use pf::web::util;
use pf::util;
use pf::node;
use pf::util::radius qw(perform_coa perform_disconnect);
use pf::security_event qw(security_event_count_reevaluate_access);
use pf::radius::constants;
use pf::locationlog qw(locationlog_get_session);

sub description { 'Mist' }

=head1 SUBROUTINES

=over

=cut

# CAPABILITIES
# access technology supported
sub supportsWirelessDot1x { return $TRUE; }
sub supportsWirelessMacAuth { return $TRUE; }
sub supportsRoleBasedEnforcement { return $TRUE; }
sub supportsWiredMacAuth { return $TRUE; }
sub supportsWiredDot1x { return $TRUE; }

# disabling special features supported by generic Cisco's but not on WLCs
sub supportsSaveConfig { return $FALSE; }
sub supportsCdp { return $FALSE; }
sub supportsLldp { return $FALSE; }
# inline capabilities
sub inlineCapabilities { return ($MAC,$SSID); }
sub supportsExternalPortal { return $TRUE; }

=item deauthenticateMacDefault

De-authenticate a MAC address from wireless network (including 802.1x).

New implementation using RADIUS Disconnect-Request.

=cut

sub deauthenticateMacDefault {
    my ( $self, $mac, $is_dot1x ) = @_;
    my $logger = $self->logger;

    if ( !$self->isProductionMode() ) {
        $logger->info("not in production mode... we won't perform deauthentication");
        return 1;
    }

    $logger->debug("deauthenticate $mac using RADIUS Disconnect-Request deauth method");
    # TODO push Login-User => 1 (RFC2865) in pf::radius::constants if someone ever reads this
    # (not done because it doesn't exist in current branch)
    return $self->radiusDisconnect( $mac, { 'Service-Type' => 'Login-User'} );
}

=item _deauthenticateMacSNMP

deauthenticate a MAC address from wireless network (including 802.1x)

This implementation is deprecated since RADIUS Disconnect-Request (aka
RFC3576 aka CoA) is better and also it no longer worked with firmware 7.2 and up.
See L<BUGS AND LIMITATIONS> for details.

=cut

sub _deauthenticateMacSNMP {
    my ( $self, $mac ) = @_;
    my $logger = $self->logger;
    my $OID_bsnMobileStationDeleteAction = '1.3.6.1.4.1.14179.2.1.4.1.22';

    if ( !$self->isProductionMode() ) {
        $logger->info(
            "not in production mode ... we won't write to the bnsMobileStationTable"
        );
        return 1;
    }

    if ( !$self->connectWrite() ) {
        return 0;
    }

    #format MAC
    if ( length($mac) == 17 ) {
        my $completeOid = $OID_bsnMobileStationDeleteAction . "." . mac2dec($mac);
        $logger->trace(
            "SNMP set_request for bsnMobileStationDeleteAction: $completeOid"
        );
        my $result = $self->{_sessionWrite}->set_request(
            -varbindlist => [ $completeOid, Net::SNMP::INTEGER, 1 ] );
        # TODO: validate result
        $logger->info("deauthenticate mac $mac from controller: ".$self->{_ip});
        return ( defined($result) );
    } else {
        $logger->error(
            "ERROR: MAC format is incorrect ($mac). Should be xx:xx:xx:xx:xx:xx"
        );
        return 1;
    }
}

sub blacklistMac {
    my ( $self, $mac, $description ) = @_;
    my $logger = $self->logger;

    if ( length($mac) == 17 ) {

        my $session;
        eval {
            require Net::Telnet;
            $session = Net::Telnet->new(
                Host    => $self->{_ip},
                Timeout => 5,
                Prompt  => '/[\$%#>]$/'
            );
            $session->waitfor('/User: /');
            $session->put( $self->{_cliUser} . "\n" );
            $session->waitfor('/Password:/');
            $session->put( $self->{_cliPwd} . "\n" );
            $session->waitfor( $session->prompt );
        };

        if ($@) {
            $logger->error(
                "ERROR: Can not connect to access point $self->{'_ip'} using telnet"
            );
            return 1;
        }
        $logger->info("Blacklisting mac $mac");
        $session->cmd("config exclusionlist add $mac");
        $session->cmd(
            "config exclusionlist description $mac \"$description\"");
        $session->close();
    }
    return 1;
}

sub isLearntTrapsEnabled {
    my ( $self, $ifIndex ) = @_;
    return ( 0 == 1 );
}

sub setLearntTrapsEnabled {
    my ( $self, $ifIndex, $trueFalse ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return -1;
}

sub isRemovedTrapsEnabled {
    my ( $self, $ifIndex ) = @_;
    return ( 0 == 1 );
}

sub setRemovedTrapsEnabled {
    my ( $self, $ifIndex, $trueFalse ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return -1;
}

sub getVmVlanType {
    my ( $self, $ifIndex ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return -1;
}

sub setVmVlanType {
    my ( $self, $ifIndex, $type ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return -1;
}

sub isTrunkPort {
    my ( $self, $ifIndex ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return -1;
}

sub getVlans {
    my ($self) = @_;
    my $vlans  = {};
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return $vlans;
}

sub isDefinedVlan {
    my ( $self, $vlan ) = @_;
    my $logger = $self->logger;
    $logger->error("function is NOT implemented");
    return 0;
}

sub isVoIPEnabled {
    my ($self) = @_;
    return 0;
}

=item returnRoleAttribute

What RADIUS Attribute (usually VSA) should the role returned into.

=cut

sub returnRoleAttribute {
    my ($self) = @_;

    return 'Airespace-ACL-Name';
}

=item deauthTechniques

Return the reference to the deauth technique or the default deauth technique.

=cut

sub deauthTechniques {
    my ($self, $method) = @_;
    my $logger = $self->logger;
    my $default = $SNMP::RADIUS;
    my %tech = (
        $SNMP::RADIUS => 'deauthenticateMacDefault',
        $SNMP::SNMP  => '_deauthenticateMacSNMP',
    );

    if (!defined($method) || !defined($tech{$method})) {
        $method = $default;
    }
    return $method,$tech{$method};
}

=item returnAuthorizeWrite

Return radius attributes to allow write access

=cut

sub returnAuthorizeWrite {
    my ($self, $args) = @_;
    my $logger = $self->logger;
    my $radius_reply_ref;
    my $status;
    $radius_reply_ref->{'Service-Type'} = 'Administrative-User';
    $radius_reply_ref->{'Reply-Message'} = "Switch enable access granted by PacketFence";
    $logger->info("User $args->{'user_name'} logged in $args->{'switch'}{'_id'} with write access");
    my $filter = pf::access_filter::radius->new;
    my $rule = $filter->test('returnAuthorizeWrite', $args);
    ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule,$args,$radius_reply_ref);
    return [$status, %$radius_reply_ref];

}

=item returnAuthorizeRead

Return radius attributes to allow read access

=cut

sub returnAuthorizeRead {
    my ($self, $args) = @_;
    my $logger = $self->logger;
    my $radius_reply_ref;
    my $status;
    $radius_reply_ref->{'Service-Type'} = 'NAS-Prompt-User';
    $radius_reply_ref->{'Reply-Message'} = "Switch read access granted by PacketFence";
    $logger->info("User $args->{'user_name'} logged in $args->{'switch'}{'_id'} with read access");
    my $filter = pf::access_filter::radius->new;
    my $rule = $filter->test('returnAuthorizeRead', $args);
    ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule,$args,$radius_reply_ref);
    return [$status, %$radius_reply_ref];
}

=item returnRadiusAccessAccept

Prepares the RADIUS Access-Accept reponse for the network device.

Overrides the default implementation to add the dynamic acls

=cut

sub returnRadiusAccessAccept {
    my ($self, $args) = @_;
    my $logger = $self->logger;

    $args->{'unfiltered'} = $TRUE;
    my @super_reply = @{$self->SUPER::returnRadiusAccessAccept($args)};
    my $status = shift @super_reply;
    my %radius_reply = @super_reply;
    my $radius_reply_ref = \%radius_reply;
    return [$status, %$radius_reply_ref] if($status == $RADIUS::RLM_MODULE_USERLOCK);

    my @av_pairs = defined($radius_reply_ref->{'Cisco-AVPair'}) ? @{$radius_reply_ref->{'Cisco-AVPair'}} : ();

    my $role = $self->getRoleByName($args->{'user_role'});
    if ( isenabled($self->{_UrlMap}) && $self->externalPortalEnforcement ) {
        if ( defined($args->{'user_role'}) && $args->{'user_role'} ne "" && defined($self->getUrlByName($args->{'user_role'}) ) ) {
            $args->{'session_id'} = "sid".$self->setSession($args);
            my $redirect_url = $self->getUrlByName($args->{'user_role'});
            $redirect_url .= '/' unless $redirect_url =~ m(\/$);
            $redirect_url .= $args->{'session_id'};
            # Cisco and Meraki started adding "&redirect_url=http://example.com" unconditionnaly to the redirect URL.
            # This means that since we don't have any query parameters that generated paths like "/Cisco::WLC/sid123456&redirect_url=http://example.com" which extracts the SID as sid123456&redirect_url=http://example.com
            # We add empty query parameters to our path as a workaround
            $redirect_url .= "?";
            #override role if a role in role map is define
            if (isenabled($self->{_RoleMap}) && $self->supportsRoleBasedEnforcement()) {
                my $role_map = $self->getRoleByName($args->{'user_role'});
                $role = $role_map if (defined($role_map));
                # remove the role if any as we push the redirection ACL along with it's role
                delete $radius_reply_ref->{$self->returnRoleAttribute()};
            }
            $logger->info("Adding web authentication redirection to reply using role: '$role' and URL: '$redirect_url'");
            push @av_pairs, "url-redirect-acl=$role";
            push @av_pairs, "url-redirect=".$redirect_url;
        }
    }
    if ($args->{profile}->dpskEnabled()) {
        if (defined($args->{owner}->{psk})) {
            push @av_pairs, "psk=$args->{owner}->{psk}";
        } else {
            push @av_pairs, "psk=$args->{profile}->{_default_psk_key}";
        }
        push @av_pairs, "psk-mode=ascii";
    }

    $radius_reply_ref->{'Cisco-AVPair'} = \@av_pairs;

    my $filter = pf::access_filter::radius->new;
    my $rule = $filter->test('returnRadiusAccessAccept', $args);
    ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule,$args,$radius_reply_ref);
    return [$status, %$radius_reply_ref];
}

=item radiusDisconnect

Sends a RADIUS Disconnect-Request to the NAS with the MAC as the Calling-Station-Id to disconnect.

Optionally you can provide other attributes as an hashref.

Uses L<pf::util::radius> for the low-level RADIUS stuff.

=cut

# TODO consider whether we should handle retries or not?


sub radiusDisconnect {
    my ($self, $mac, $add_attributes_ref) = @_;
    my $logger = $self->logger;

    # initialize
    $add_attributes_ref = {} if (!defined($add_attributes_ref));

    if (!defined($self->{'_radiusSecret'})) {
        $logger->warn(
            "Unable to perform RADIUS CoA-Request on (".$self->{'_id'}."): RADIUS Shared Secret not configured"
        );
        return;
    }

    $logger->info("deauthenticating");

    # Where should we send the RADIUS CoA-Request?
    # to network device by default
    my $send_disconnect_to = $self->{'_ip'};
    # but if controllerIp is set, we send there
    if (defined($self->{'_controllerIp'}) && $self->{'_controllerIp'} ne '') {
        $logger->info("controllerIp is set, we will use controller $self->{_controllerIp} to perform deauth");
        $send_disconnect_to = $self->{'_controllerIp'};
    }
    # On which port we have to send the CoA-Request ?
    my $nas_port = $self->{'_disconnectPort'} || '3799';
    my $coa_port = $self->{'_coaPort'} || '3799';
    # allowing client code to override where we connect with NAS-IP-Address
    $send_disconnect_to = $add_attributes_ref->{'NAS-IP-Address'}
        if (defined($add_attributes_ref->{'NAS-IP-Address'}));

    my $response;
    try {
        my $connection_info = {
            nas_ip => $send_disconnect_to,
            secret => $self->{'_radiusSecret'},
            LocalAddr => $self->deauth_source_ip($send_disconnect_to),
            nas_port => $coa_port,
        };

        $logger->debug("network device (".$self->{'_id'}.") supports roles. Evaluating role to be returned");
        my $roleResolver = pf::roles::custom->instance();
        my $role = $roleResolver->getRoleForNode($mac, $self);

        my $node_info = node_view($mac);
        # transforming MAC to the expected format 00-11-22-33-CA-FE
        $mac = uc($mac);
        $mac =~ s/:/-/g;
        # Standard Attributes

        my $attributes_ref = {
            'Calling-Station-Id' => $mac,
            'NAS-IP-Address' => $send_disconnect_to,
            'NAS-Port' => $node_info->{'last_port'},
        };
        # merging additional attributes provided by caller to the standard attributes
        $attributes_ref = { %$attributes_ref, %$add_attributes_ref };
	
	my $vsa = [{
		vendor => "Cisco",
		attribute => "Cisco-AVPair",
		value => "subscriber:command=reauthenticate",
	}];
	$connection_info = {
	nas_ip => $send_disconnect_to,
	secret => $self->{'_radiusSecret'},
	LocalAddr => $self->deauth_source_ip($send_disconnect_to),
	nas_port => $nas_port,
    };
	#force CoA as the checkbox in packetfence doesn't use the if statement that was previous configured.
	$response = perform_coa($connection_info, $attributes_ref, $vsa);
    } catch {
        chomp;
        $logger->warn("Unable to perform RADIUS CoA-Request on (".$self->{'_id'}."): $_");
        $logger->error("Wrong RADIUS secret or unreachable network device (".$self->{'_id'}.")... On some Cisco Wireless Controllers you might have to set disconnectPort=1700 as some versions ignore the CoA requests on port 3799") if ($_ =~ /^Timeout/);
    };
    return if (!defined($response));

    return $TRUE if ( ($response->{'Code'} eq 'Disconnect-ACK') || ($response->{'Code'} eq 'CoA-ACK') );

    $logger->warn(
        "Unable to perform RADIUS Disconnect-Request on (".$self->{'_id'}.")."
        . ( defined($response->{'Code'}) ? " $response->{'Code'}" : 'no RADIUS code' ) . ' received'
        . ( defined($response->{'Error-Cause'}) ? " with Error-Cause: $response->{'Error-Cause'}." : '' )
    );
    return;
}

=item parseRequest

Redefinition of pf::Switch::parseRequest due to specific attribute being used for webauth

=cut

sub parseRequest {
    my ( $self, $radius_request ) = @_;
    my $client_mac      = ref($radius_request->{'Calling-Station-Id'}) eq 'ARRAY'
                           ? clean_mac($radius_request->{'Calling-Station-Id'}[0])
                           : clean_mac($radius_request->{'Calling-Station-Id'});
    my $user_name       = $self->parseRequestUsername($radius_request);
    my $nas_port_type   = $radius_request->{'NAS-Port-Type'};
    my $port            = $radius_request->{'NAS-Port'};
    my $eap_type        = ( exists($radius_request->{'EAP-Type'}) ? $radius_request->{'EAP-Type'} : 0 );
    my $nas_port_id     = ( defined($radius_request->{'NAS-Port-Id'}) ? $radius_request->{'NAS-Port-Id'} : undef );
    my $session_id = $self->getCiscoAvPairAttribute($radius_request, 'audit-session-id');

    return ($nas_port_type, $eap_type, $client_mac, $port, $user_name, $nas_port_id, $session_id, $nas_port_id);
}

=item parseExternalPortalRequest

Parse external portal request using URI and it's parameters then return an hash reference with the appropriate parameters

See L<pf::web::externalportal::handle>

=cut

sub parseExternalPortalRequest {
    my ( $self, $r, $req ) = @_;
    my $logger = $self->logger;

    # Using a hash to contain external portal parameters
    my %params = ();

    # Cisco WLC uses external portal session ID handling process
    my $uri = $r->uri;
    return unless ($uri =~ /.*sid(.*[^\/])/);
    my $session_id = $1;

    my $locationlog = pf::locationlog::locationlog_get_session($session_id);
    my $switch_id = $locationlog->{switch};
    my $client_mac = $locationlog->{mac};
    my $client_ip = defined($r->headers_in->{'X-Forwarded-For'}) ? $r->headers_in->{'X-Forwarded-For'} : $r->connection->remote_ip;

    my $redirect_url;
    if ( defined($req->param('redirect')) ) {
        $redirect_url = $req->param('redirect');
    }
    elsif ( defined($req->param('redirect_url')) ) {
        $redirect_url = $req->param('redirect_url');
    }
    elsif ( defined($r->headers_in->{'Referer'}) ) {
        $redirect_url = $r->headers_in->{'Referer'};
    }

    if($redirect_url !~ /^http/) {
        $redirect_url = "http://".$redirect_url;
    }

    %params = (
        session_id              => $session_id,
        switch_id               => $switch_id,
        client_mac              => $client_mac,
        client_ip               => $client_ip,
        redirect_url            => $redirect_url,
        synchronize_locationlog => $FALSE,
        connection_type         => $WEBAUTH_WIRELESS,
    );

    return \%params;
}


=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2019 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
