%global pypi_name krest

Name:           python-%{pypi_name}
Version:        1.2.2
Release:        1%{?dist}
Summary:        Python client for Kaminario K2 REST interface

License:        Proprietary
URL:            https://github.com/krest/krest-py
Source0:        https://pypi.python.org/packages/source/p/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch
 
BuildRequires:  python-devel
 
Requires:       python-requests >= 2.0.0

%description
=============================================
Python client for Kaminario K2 REST interface
=============================================

%prep
%setup -q -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info



%build
%{__python} setup.py build


%install
%{__python} setup.py install --skip-build --root %{buildroot}


%files
%{python_sitelib}/%{pypi_name}.py*
%{python_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info

%changelog
* Tue Nov 19 2013 root - 0.1.2-1
- Initial package.
