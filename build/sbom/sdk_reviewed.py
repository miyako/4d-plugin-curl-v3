"""Frozen reviewed SDK evidence; update only after an explicit vendor review.

All SHA-256 values are literals: HASHES covers exact reviewed bytes, LF_HASHES
normalizes CRLF/lone CR to LF, and CRLF_HASHES converts that LF form to CRLF.
No repository files are read when this module is imported.
"""

SDK_PIN = {'schema_version': 1,
 'repository': 'https://github.com/4d/4D-Plugin-SDK',
 'commit': 'ad7944bc7a13d93db8097c4c8ff55ba2f6e36f86',
 'tree': 'db4adb91d6060dd891cd4fc02b42899ab2890bf7',
 'author_date': '2025-07-11T12:08:54Z',
 'committer_date': '2026-11-06T09:46:19Z',
 'selection': {'branch': 'master',
               'cutoff': '2026-11-08T14:59:59Z',
               'latest_commit_before_cutoff': 'ad7944bc7a13d93db8097c4c8ff55ba2f6e36f86',
               'verification_url': 'https://api.github.com/repos/4d/4D-Plugin-SDK/commits?sha=master&until=2026-11-08T14:59:59Z&per_page=1'},
 'scope': 'Top-level 4D Plugin API files only; local Classes and repository root licensing are preserved.',
 'hash_algorithm': 'SHA-256',
 'files': [{'path': '4D Plugin API/4DPluginAPI.c',
            'upstream_path': '4D Plugin API/4DPluginAPI.c',
            'before_sha256': '5bac571c5c4cafd280fa7f23d775458a23701287e8735be27d4a2190002f4e3f',
            'after_sha256': '91fae4e018fe7e63d56f2f0f6fe002ab46853a28380113735393bbe82fb783ab',
            'upstream_sha256': '91fae4e018fe7e63d56f2f0f6fe002ab46853a28380113735393bbe82fb783ab',
            'upstream_blob_sha': '01f07152c86e0b29eca1591b7e4a45515c1c436c'},
           {'path': '4D Plugin API/4DPluginAPI.def',
            'upstream_path': '4D Plugin API/4DPluginAPI.def',
            'before_sha256': 'ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2',
            'after_sha256': 'ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2',
            'upstream_sha256': 'ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2',
            'upstream_blob_sha': '5bbdb82fb724b6f8e307feb01d9f158b802de89d'},
           {'path': '4D Plugin API/4DPluginAPI.h',
            'upstream_path': '4D Plugin API/4DPluginAPI.h',
            'before_sha256': 'c845a8ae3b552f514e16598605727bf5008eaa28df2401950ac2b7881df61f02',
            'after_sha256': '054977f36970d95ff1ee665707812a2afcbc35ffdcad439c51995e71303de6de',
            'upstream_sha256': '054977f36970d95ff1ee665707812a2afcbc35ffdcad439c51995e71303de6de',
            'upstream_blob_sha': '5b7f6fe94344cfef38011279d68f0b680b7f062b'},
           {'path': '4D Plugin API/EntryPoints.h',
            'upstream_path': '4D Plugin API/EntryPoints.h',
            'before_sha256': '60afb0b833c95d6c47b88d2d0eba0fb212c2c6b53a44e3cfc0b4c6956d25d2dd',
            'after_sha256': '0deb73e2c1550160fe74b170828c16e03e619452866debe559f4b4606ce2c4b3',
            'upstream_sha256': '0deb73e2c1550160fe74b170828c16e03e619452866debe559f4b4606ce2c4b3',
            'upstream_blob_sha': '9e65f10c12a164f4df159bf2eef8711847429e2d'},
           {'path': '4D Plugin API/Flags.h',
            'upstream_path': '4D Plugin API/Flags.h',
            'before_sha256': 'c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b',
            'after_sha256': 'c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b',
            'upstream_sha256': 'c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b',
            'upstream_blob_sha': '7a5a35539f27430a3fd9cb711d6b789051316471'},
           {'path': '4D Plugin API/PrivateTypes.h',
            'upstream_path': '4D Plugin API/PrivateTypes.h',
            'before_sha256': '329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f',
            'after_sha256': '329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f',
            'upstream_sha256': '329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f',
            'upstream_blob_sha': 'a3098cb662cdbc43ba574fdef72a059c4c6d1cd4'},
           {'path': '4D Plugin API/PublicTypes.h',
            'upstream_path': '4D Plugin API/PublicTypes.h',
            'before_sha256': '7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155',
            'after_sha256': '7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155',
            'upstream_sha256': '7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155',
            'upstream_blob_sha': '9ae20b001bff9128f690fff3e6c3f873b6238333'},
           {'path': '4D Plugin API/Readme.md',
            'upstream_path': '4D Plugin API/Readme.md',
            'before_sha256': 'e33b61a7ff7fb8f079095c7684e37237a41808dad41f9a454161ed8827b4bd8a',
            'after_sha256': 'e33b61a7ff7fb8f079095c7684e37237a41808dad41f9a454161ed8827b4bd8a',
            'upstream_sha256': 'e33b61a7ff7fb8f079095c7684e37237a41808dad41f9a454161ed8827b4bd8a',
            'upstream_blob_sha': 'c48263032a5a4ab4a7749b48a3c9e7c6062231ef'},
           {'path': '4D Plugin API/LICENSE.md',
            'upstream_path': 'LICENSE.md',
            'before_sha256': None,
            'after_sha256': '3ec16157270f99f94e461cb5fb3da1ccd6486400829244f3b98860b94481f1d0',
            'upstream_sha256': '3ec16157270f99f94e461cb5fb3da1ccd6486400829244f3b98860b94481f1d0',
            'upstream_blob_sha': '40eab2ad6d0b4c2fffc607d9fd7d631df0a8a454'}],
 'license': {'spdx_id': 'MIT',
             'path': '4D Plugin API/LICENSE.md',
             'upstream_path': 'LICENSE.md',
             'sha256': '3ec16157270f99f94e461cb5fb3da1ccd6486400829244f3b98860b94481f1d0'},
 'compatibility_patches': [],
 'compatibility_review': ['Use upstream VERSIONMAC rather than the old local __APPLE__ CoreGraphics guard; '
                          'Flags.h derives VERSIONMAC from __APPLE__ on the supported Apple target.',
                          'Accept upstream zero-initialized object/JSON parameter arrays, '
                          'PA_GetPointerParameter PA_IsCompiled(0) correction, and the added '
                          'PA_ReturnVariable declaration/implementation. The plugin does not call '
                          'PA_GetPointerParameter or PA_ReturnVariable.',
                          '4DPluginAPI.def, Flags.h, PrivateTypes.h, PublicTypes.h and Readme.md were '
                          'already byte-identical to this upstream commit and were refreshed without local '
                          'changes.',
                          'Before removal, no first-party source used Json:: or libjson APIs; only the '
                          'unused json/json.h include and build include/link references remained. Native '
                          'support/4DPlugin-JSON.* uses 4D PA_* APIs and is preserved.',
                          'All nine vendored SDK files are pristine upstream bytes. Remove the eleven former local setter fFiller assignments; initialization belongs to first-party callers.',
                          'Reviewed every first-party PA_Set*Variable call in 4DPlugin-cURL.cpp, support and Classes. Every scalar setter destination is initialized by PA_CreateVariable; callback array elements are initialized by their existing branch-specific PA_CreateVariable assignments. Classes copies host variables and has no PA_Set*Variable calls; preserve those values.',
                          "No first-party source changes are necessary: ob_stringify already assigns PA_CreateVariable(eVK_Object) to _params[0] before its setter; delay params[2] assigns PA_CreateVariable to both elements; callback branches initialize every used argument with PA_CreateVariable. The lone params is passed with argument count zero, so it is not read. Preserve these existing assignments, callback variants and host-variable copies."]}

HASHES = {'4D Plugin API/4DPluginAPI.c': '91fae4e018fe7e63d56f2f0f6fe002ab46853a28380113735393bbe82fb783ab',
 '4D Plugin API/4DPluginAPI.def': 'ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2',
 '4D Plugin API/4DPluginAPI.h': '054977f36970d95ff1ee665707812a2afcbc35ffdcad439c51995e71303de6de',
 '4D Plugin API/EntryPoints.h': '0deb73e2c1550160fe74b170828c16e03e619452866debe559f4b4606ce2c4b3',
 '4D Plugin API/Flags.h': 'c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b',
 '4D Plugin API/LICENSE.md': '3ec16157270f99f94e461cb5fb3da1ccd6486400829244f3b98860b94481f1d0',
 '4D Plugin API/PrivateTypes.h': '329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f',
 '4D Plugin API/PublicTypes.h': '7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155',
 '4D Plugin API/Readme.md': 'e33b61a7ff7fb8f079095c7684e37237a41808dad41f9a454161ed8827b4bd8a'}

CRLF_HASHES = {'4D Plugin API/4DPluginAPI.c': '98c791e3ebad524f7b1adcbba63db9d5bbeb89308f1c6f35f6751f48af0dcf10',
 '4D Plugin API/4DPluginAPI.def': 'db4ccfe9dac3e987ddd8c1a143528b51dfb16425a2e65dcafb930c214dc4ba87',
 '4D Plugin API/4DPluginAPI.h': 'e7b92e3cb837b337cdeb4f3b1a423c33b16bcae9eef47bafffbc5f21d34a0890',
 '4D Plugin API/EntryPoints.h': '770ac6aed9f7c89ada2906ad2859636c357a079aca398f9c41d6583260e3b599',
 '4D Plugin API/Flags.h': '8252981f0c6f99a16ba080933d04e2a0770d9aed50034b799d2e2cd481bd4fe5',
 '4D Plugin API/LICENSE.md': '197063d3232d46c501234e34249ab95d255cbaf3e719b6c215dbf2aa8d49f877',
 '4D Plugin API/PrivateTypes.h': '421afd3e6178c308fe053fd6b25469c2cf17557f95df91cca723face35083cb5',
 '4D Plugin API/PublicTypes.h': 'a166bbadc0b8dcd3bf2e21b5eaf879eb32968a7edce87b3958ae724701f5db93',
 '4D Plugin API/Readme.md': '84af3d6e6f56b599e6feec0359e6e22712f5f90480359bd4dd0e0f194f012732'}

LF_HASHES = {'4D Plugin API/4DPluginAPI.c': '91fae4e018fe7e63d56f2f0f6fe002ab46853a28380113735393bbe82fb783ab',
 '4D Plugin API/4DPluginAPI.def': 'ab72ac2a2e371e8ef97c1d0c9bb9597af6f21a8f2a1429ce839817ca800197b2',
 '4D Plugin API/4DPluginAPI.h': '054977f36970d95ff1ee665707812a2afcbc35ffdcad439c51995e71303de6de',
 '4D Plugin API/EntryPoints.h': '0deb73e2c1550160fe74b170828c16e03e619452866debe559f4b4606ce2c4b3',
 '4D Plugin API/Flags.h': 'c39ca489cb5dacd2ebcbb95d914795c60d557b87acc2456f6abf3fd63d66850b',
 '4D Plugin API/LICENSE.md': '3ec16157270f99f94e461cb5fb3da1ccd6486400829244f3b98860b94481f1d0',
 '4D Plugin API/PrivateTypes.h': '329a5ba0d0369b4e96ad9afe4d0261407164dbf4c1379c5bbe1685669d20a53f',
 '4D Plugin API/PublicTypes.h': '7b8c3959f24267a2a398680ddd114acc14b33082974b1debc2a940a82cdb6155',
 '4D Plugin API/Readme.md': 'e33b61a7ff7fb8f079095c7684e37237a41808dad41f9a454161ed8827b4bd8a'}

SDK_LICENSE_TEXT = ('MIT License\n'
 '\n'
 'Copyright (c) 2017-present, 4D, Inc.\n'
 '\n'
 'Permission is hereby granted, free of charge, to any person obtaining a copy\n'
 'of this software and associated documentation files (the "Software"), to deal\n'
 'in the Software without restriction, including without limitation the rights\n'
 'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n'
 'copies of the Software, and to permit persons to whom the Software is\n'
 'furnished to do so, subject to the following conditions:\n'
 '\n'
 'The above copyright notice and this permission notice shall be included in all\n'
 'copies or substantial portions of the Software.\n'
 '\n'
 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
 'IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n'
 'FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n'
 'AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n'
 'LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n'
 'OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n'
 'SOFTWARE.')
