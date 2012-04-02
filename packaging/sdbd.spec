Name:       sdbd
Summary:    SDB daemon
Version: 0.0.2
Release:    1
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz

%description
Description: SDB daemon


%prep
%setup -q

%build
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_sysconfdir}/init.d/sdbd

%ifarch %{ix86}
%{_sysconfdir}/rc.d/rc3.d
%endif

%changelog
* Sat Mar 31 2012 Yoonki Park <yoonki.park@samsung.com>
 - let sshd be daemon and create sshd.pid file
