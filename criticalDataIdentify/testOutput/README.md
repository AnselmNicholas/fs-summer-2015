#Summary


##ghttpd
Unable to find `excel` in all trace.
- ghttpd-trace-abnormal
- ghttpd-trace-cgi
- ghttpd-trace-cgi-tainted
- ghttpd-trace-init

##nginx
Unable to find `unlink`, `seteuid`, `setreuid` in all trace.
- nginx-trace-abnormal
- nginx-trace-abnormal-nodebug
- nginx-trace-init
- nginx-trace-init-nodebug
- nginx-trace-normal
- nginx-trace-normal-tainted-nodebug
- nginx-trace-rootdir-nodebug

##nullhttpd
Unable to find `excel` in all trace.
- nullhttpd-attack
- nullhttpd-normal

##sudo
- sudo-trace-abnormal
- sudo-trace-normal-child
 - Found critical data for `setuid` in 1 frame.
- sudo-trace-normal-tainted
- sudo-trace-setresuid
 - Unable to find `setresuid` in trace.

##wuftp
- wuftp-trace-abnormal
- wuftp-trace-init
- wuftp-trace-normal
 - Found critical data for `seteuid` in 3 frame.
- wuftp-trace-passive
 - Found critical data for `seteuid` in 1 frame.
- wuftp-trace-user

Updated on 03 June 2015, 02:08 AM.
