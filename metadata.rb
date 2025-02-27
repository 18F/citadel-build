#
# Copyright 2016, Noah Kantrowitz
# Copyright 2017, U.S. General Services Administration
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

name "citadel_fork"
version "9.2.0"
description "18F FORK -- DSL for accessing secret data stored on S3 using IAM roles."
long_description "# Citadel Cookbook\n\n[![Build Status](https://img.shields.io/travis/poise/citadel.svg)](https://travis-ci.org/poise/citadel)\n[![Gem Version](https://img.shields.io/gem/v/poise-citadel.svg)](https://rubygems.org/gems/poise-citadel)\n[![Cookbook Version](https://img.shields.io/cookbook/v/citadel.svg)](https://supermarket.chef.io/cookbooks/citadel)\n[![Coverage](https://img.shields.io/codecov/c/github/poise/citadel.svg)](https://codecov.io/github/poise/citadel)\n[![Gemnasium](https://img.shields.io/gemnasium/poise/citadel.svg)](https://gemnasium.com/poise/citadel)\n[![License](https://img.shields.io/badge/license-Apache_2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)\n\nUsing a combination of IAM roles, S3 buckets, and EC2 it is possible to use AWS\nas a trusted-third-party for distributing secret or otherwise sensitive data.\n\n## Overview\n\nIAM roles allow specifying snippets of IAM policies in a way that can be used\nfrom an EC2 virtual machine. Combined with a private S3 bucket, this can be\nused to authorize specific hosts to specific files.\n\nIAM Roles can be created [in the AWS Console](https://console.aws.amazon.com/iam/home#roles).\nWhile the policies applied to a role can be changed later, the name cannot so\nbe careful when choosing them.\n\n## Requirements\n\nThis cookbook requires Chef 12 or newer. It also requires the EC2 ohai plugin\nto be active. If you are using a VPC, this may require setting the hint file\ndepending on your version of Ohai/Chef:\n\n```bash\n$ mkdir -p /etc/chef/ohai/hints\n$ touch /etc/chef/ohai/hints/ec2.json\n```\n\nIf you use knife-ec2 to start the instance, the hint file is already set for you.\n\n## IAM Policy\n\nBy default, your role will not be able to access any files in your private S3\nbucket. You can create IAM policies that whitelist specific keys for each role:\n\n```json\n{\n  \"Version\": \"2008-10-17\",\n  \"Id\": \"<policy name>\",\n  \"Statement\": [\n    {\n      \"Sid\": \"<statement name>\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::<AWS account number>:role/<role name>\"\n      },\n      \"Action\": \"s3:GetObject\",\n      \"Resource\": \"arn:aws:s3:::<bucket name>/<key pattern>\"\n    }\n  ]\n}\n```\n\nThe key pattern can include `*` and `?` metacharacters, so for example\n`arn:aws:s3:::myapp.citadel/deploy_keys/*` to allow access to all files in the\n`deploy_keys` folder.\n\nThis policy can be attached to either the IAM role or the S3 bucket with equal\neffect.\n\n## Limitations\n\nEach EC2 VM can only be assigned a single IAM role. This can complicate situations\nwhere some secrets need to be shared by overlapping subsets of your servers. A\npossible improvement to this would be to make a script to create all needed\ncomposite IAM roles, possibly driven by Chef roles or other metadata.\n\n## Attributes\n\n* `node['citadel']['bucket']` – The default S3 bucket to use.\n\n## Recipe Usage\n\nYou can access secret data via the `citadel` method.\n\n```ruby\nfile '/etc/secret' do\n  owner 'root'\n  group 'root'\n  mode '600'\n  content citadel['keys/secret.pem']\nend\n```\n\nBy default the node attribute `node['citadel']['bucket']` is used to find the\nS3 bucket to query, however you can override this:\n\n```ruby\ntemplate '/etc/secret' do\n  owner 'root'\n  group 'root'\n  mode '600'\n  variables secret: citadel('mybucket')['id_rsa']\nend\n```\n\n## Developing with Vagrant\n\nWhile developing in a local VM, you can use the node attributes\n`node['citadel']['access_key_id']` and `node['citadel']['secret_access_key']`\nto provide credentials. The recommended way to do this is via environment variables\nso that the Vagrantfile itself can still be kept in source control without\nleaking credentials:\n\n```ruby\nconfig.vm.provision :chef_solo do |chef|\n  chef.json = {\n    citadel: {\n      access_key_id: ENV['ACCESS_KEY_ID'],\n      secret_access_key: ENV['SECRET_ACCESS_KEY'],\n    },\n  }\nend\n```\n\n**WARNING:** Use of these attributes in production should be considered a likely\nsecurity risk as they will end up visible in the node data, or in the role/environment/cookbook\nthat sets them. This can be mitigated using Enterprise Chef ACLs, however such\nconfigurations are generally error-prone due to the defaults being wide open.\n\n### Testing with Test-Kitchen\n\nSimilarly you can use the same attributes with Test-Kitchen\n\n```yaml\nprovisioner:\n  name: chef_solo\n  attributes:\n    citadel:\n      access_key_id: <%= ENV['AWS_ACCESS_KEY_ID'] %>\n      secret_access_key: <%= ENV['AWS_SECRET_ACCESS_KEY'] %>\n```\n\n## Recommended S3 Layout\n\nWithin your S3 bucket I recommend you create one folder for each group of\nsecrets, and in your IAM policies have one statement per group. Each group of\nsecrets is a set of data with identical security requirements. Many groups will\nstart out only containing a single file, however having the flexibility to\nchange this in the future allows for things like key rotation without rewriting\nall of your IAM policies.\n\nAn example of an IAM policy resource would be:\n\n```\n\"Resource\": \"arn:aws:s3:::mybucket/myfolder/*\"\n```\n\n## Creating and Updating Secrets\n\nYou can use any S3 client you prefer to manage your secrets, however make sure\nthat new files are set to private (accessible only to the creating user) by\ndefault.\n\n## Sponsors\n\nThe Poise test server infrastructure is sponsored by [Rackspace](https://rackspace.com/).\n\n## License\n\nCopyright 2013-2016, Balanced, Inc.\nCopyright 2016, Noah Kantrowitz\n\nLicensed under the Apache License, Version 2.0 (the \"License\");\nyou may not use this file except in compliance with the License.\nYou may obtain a copy of the License at\n\nhttp://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by applicable law or agreed to in writing, software\ndistributed under the License is distributed on an \"AS IS\" BASIS,\nWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\nSee the License for the specific language governing permissions and\nlimitations under the License.\n"
maintainer "Noah Kantrowitz"
maintainer_email "noah@coderanger.net"
source_url "https://github.com/poise/citadel" if defined?(source_url)
issues_url "https://github.com/poise/citadel/issues" if defined?(issues_url)
license "Apache-2.0"
chef_version ">= 12" if defined?(chef_version)
supports "aix"
supports "amazon"
supports "arch"
supports "centos"
supports "chefspec"
supports "debian"
supports "dragonfly4"
supports "fedora"
supports "freebsd"
supports "gentoo"
supports "ios_xr"
supports "mac_os_x"
supports "nexus"
supports "omnios"
supports "openbsd"
supports "opensuse"
supports "oracle"
supports "raspbian"
supports "redhat"
supports "slackware"
supports "smartos"
supports "solaris2"
supports "suse"
supports "ubuntu"
supports "windows"
