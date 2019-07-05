# Limon
# Copyright (C) 2015 Monnappa
#
# This file is part of Limon.
#
# Limon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Limon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Limon.  If not, see <http://www.gnu.org/licenses/>.


"""
@author:       Monnappa K A
@license:      GNU General Public License 3.0
@contact:      monnappa22@gmail.com
@Description:  Configuration file for Limon sandbox

@updates:      Source updated for windows
@author:       Charles Lomboni
@contact:      charleslomboni@gmail.com
"""

##############[general variables]################################
py_path = r'C:\\Python36\\python.exe'
report_dir = r'c:\\winSandbox\\reports\\'
ssdeep_path = r"C:\\tools\ssdeep-2.14.1\\ssdeep.exe"
dash_lines = "-" * 40
is_pe_file = True
virustotal_key = "PUT_YOUR_KEY_HERE"


################[static analyis variables]##########################
yara_packer_rules = r'C:\\winSandbox\\yara_rules\\Packers_index.yar'
yara_rules = r'C:\\winSandbox\\yara_rules\\Capabilities_index.yar'