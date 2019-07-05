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
@Description:  Limon Linux Sandbox - Analyses Linux Malware by performing static, dynamic and memory analysis

@updates:      Source updated for windows
@author:       Charles Lomboni
@contact:      charleslomboni@gmail.com
"""

from statanwin import *
from conf import *
from optparse import OptionParser
import shutil
import time


# checking if filename and arguments are provided
if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()

file_path = sys.argv[1]
mal_file = sys.argv[1]
file_name = os.path.basename(file_path)
filter_file_name = os.path.basename(file_path)

# creating and cleaning the report directory (used to store the reports)
new_report_dir = report_dir + "\\" + file_name
if os.path.isdir(new_report_dir):
    shutil.rmtree(new_report_dir)
os.mkdir(new_report_dir)
final_report = new_report_dir + "\\final_report.txt"
desk_screenshot_path = new_report_dir + "\\desktop.png"
pcap_output_path = new_report_dir + "\\output.pcap"
capture_output_path = new_report_dir + "\\capture_output.txt"


master_ssdeep_file = report_dir + "\\ssdeep_master.txt"
ascii_str_file = new_report_dir + "\\strings_ascii.txt"
unicode_str_file = new_report_dir + "\\strings_unicode.txt"


# Creating the master ssdeep file
if not os.path.exists(master_ssdeep_file):
    mssdeepf = open(master_ssdeep_file, "w")
    mssdeepf.write("ssdeep,1.1--blocksize:hash:hash,filename\n")
    mssdeepf.close()

f = open(final_report, 'w')


f.write( "===========================[STATIC ANALYSIS RESULTS]===========================\n\n")
#static = Static(file_path)
static = Static(mal_file, ssdeep_path)
filetype = static.filetype()
print ("Filetype: %s" % filetype)
f.write("Filetype: %s" % filetype)
f.write("\n")

file_size = static.get_file_size()
print ("File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size))
f.write("File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size))
f.write("\n")

md5sum = static.md5sum()
print ("md5sum: %s" % md5sum)
f.write("md5sum: %s" % md5sum)
f.write("\n")

fhash = static.ssdeep()
fuzzy_hash = fhash.split(",")[0]
print ("ssdeep: %s" % fuzzy_hash)
f.write("ssdeep: %s" % fuzzy_hash)
f.write("\n")

if is_pe_file:
    pe_header = static.pe_header()
    print (pe_header)
    f.write(pe_header)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

ssdeep_compare = static.ssdeep_compare(master_ssdeep_file)
print ("ssdeep comparison:")
print (ssdeep_compare)
print (dash_lines)
f.write("ssdeep comparison:")
f.write("\n")
f.write(ssdeep_compare)
f.write("\n")
f.write(dash_lines)
f.write("\n")
fm = open(master_ssdeep_file, 'a')
fm.write(fhash + "\n")
fm.close()


asc_strings = static.ascii_strings()
fs = open(ascii_str_file, 'w')
fs.write(asc_strings)
fs.close()
print ("Strings:")
print ("\tAscii strings written to %s" % ascii_str_file)
f.write("Strings:")
f.write("\n")
f.write("\tAscii strings written to %s" % ascii_str_file)
f.write("\n")

unc_strings = static.unicode_strings()
fu = open(unicode_str_file, 'w')
fu.write(unc_strings)
fu.close()
print ("\tUnicode strings written to %s" % unicode_str_file)
print (dash_lines)
f.write("\tUnicode strings written to %s" % unicode_str_file)
f.write("\n")
f.write(dash_lines)
f.write("\n")

if is_pe_file and yara_packer_rules:
    yara_packer = str(static.yararules(yara_packer_rules))
    print ("Packers:")
    print ("\t" + yara_packer)
    print (dash_lines)
    f.write("Packers:")
    f.write("\n")
    f.write("\t" + yara_packer)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

if yara_rules:
    yara_capabilities = str(static.yararules(yara_rules))
    print ("Malware Capabilities and classification using YARA rules:")
    print ("\t" + yara_capabilities)
    print (dash_lines)
    f.write("Malware Capabilities and classification using YARA rules:")
    f.write("\n")
    f.write("\t" + yara_capabilities)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

print ("Virustotal:\n" + "\t")
f.write("Virustotal:\n" + "\t")
f.write("\n")
avresults = static.virustotal(virustotal_key)
if avresults !=None:
    avvendors = avresults.keys()
    sorted(avvendors)
    for avvendor in avvendors:
        print ("\t  " + avvendor + " ==> " + avresults[avvendor])
        f.write("\t  " + avvendor + " ==> " + avresults[avvendor])
        f.write("\n")
print (dash_lines)
f.write(dash_lines)
f.write("\n")


if is_pe_file:
    depends = static.dependencies()
    if depends:
        print ("Dependencies:")
        print (depends)
        print (dash_lines)
        f.write("Dependencies:")
        f.write("\n")
        f.write(depends)
        f.write("\n")
        f.write(dash_lines)
        f.write("\n")

    sect_header = static.section_header()
    print ("Section Header Information:")
    print (sect_header)
    print (dash_lines)
    f.write("Section Header Information:")
    f.write("\n")
    f.write(sect_header)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")




f.close()

print ("Final report is stored in %s" % new_report_dir)