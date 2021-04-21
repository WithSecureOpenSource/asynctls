import os

DIRECTORIES = [
    'src',
    'test',
    'components/asynctls' ]

def target_architectures():
    archs = os.getenv('FSARCHS', None)
    if archs:
        return archs.split(',')

    arch_map = {
        ('Darwin', 'arm64'): ['darwin'],
        ('Darwin', 'x86_64'): ['darwin'],
        ('FreeBSD', 'amd64'): ['freebsd_amd64'],
        ('Linux', 'i686'): ['linux32'],
        ('Linux', 'x86_64'): ['linux64'],
        ('OpenBSD', 'amd64'): ['openbsd_amd64'],
    }

    uname_os, _, _, _, uname_cpu = os.uname()
    assert (uname_os, uname_cpu) in arch_map
    return arch_map[(uname_os, uname_cpu)]

TARGET_DEFINES = {
    'freebsd_amd64': [],
    'linux32': ['_FILE_OFFSET_BITS=64'],
    'linux64': ['_FILE_OFFSET_BITS=64'],
    'openbsd_amd64': [],
    'darwin': []
}

TARGET_FLAGS = {
    'freebsd_amd64': '',
    'linux32': '-m32 ',
    'linux64': '',
    'openbsd_amd64': '',
    'darwin': '-mmacosx-version-min=10.13 '
}

TARGET_FRAMEWORKS = {
    'freebsd_amd64': [],
    'linux32': [],
    'linux64': [],
    'openbsd_amd64': [],
    'darwin': ['Security', 'CoreServices']
}

def libconfig_builder(env):
    env.InstallAs('fscomp-libconfig.json', '#fscomp-libconfig-${ARCH}.json')

def libconfig_parser():
    return '$ARCHBUILDDIR/components/asynctls/.fscomp/libconfig'

def pkgconfig_builder(env):
    pkgconfig = env.Substfile(
        'lib/pkgconfig/asynctls.pc',
        '#asynctls.pc.in',
        SUBST_DICT={
            '@prefix@': env['PREFIX'],
            '@libs_private@': ' '.join(
                [
                    '-Wl,-framework,{}'.format(framework)
                    for framework in TARGET_FRAMEWORKS[env['ARCH']]
                ]
            ),
        },
    )
    env.Alias(
        'install',
        env.Install(os.path.join(env['PREFIX'], 'lib/pkgconfig'), pkgconfig),
    )

def pkgconfig_parser(prefix):
    cmd = (
        'PKG_CONFIG_PATH=%s/lib/pkgconfig' % (prefix),
        'pkg-config',
        '--static',
        '--cflags',
        '--libs',
        'async',
        'fsdyn',
        'fstrace',
        'openssl',
    )
    return ' '.join(cmd)

def construct():
    ccflags = ' -g -O2 -Wall -Werror ' + os.getenv('FSCCFLAGS', '')
    linkflags = os.getenv('FSLINKFLAGS', '')
    ar_override = os.getenv('FSAR', os.getenv('FSBTAR', None))
    cc_override = os.getenv('FSCC', os.getenv('FSBTCC', None))
    ranlib_override = os.getenv('FSRANLIB', os.getenv('FSBTRANLIB', None))

    for target_arch in target_architectures():
        prefix = ARGUMENTS.get('prefix', '/usr/local')
        if ARGUMENTS.get('fscomp', 0):
            config_builder = libconfig_builder
            config_parser = libconfig_parser()
            fstracecheck = os.path.join('stage',
                                        target_arch,
                                        'components',
                                        'fstrace',
                                        'etc',
                                        'fstracecheck.py')
        else:
            config_builder = pkgconfig_builder
            config_parser = pkgconfig_parser(prefix)
            fstracecheck = os.path.join(prefix, 'bin', 'fstracecheck')

        target_ccflags = TARGET_FLAGS[target_arch] + ccflags
        target_cppdefines = TARGET_DEFINES[target_arch]
        target_frameworks = TARGET_FRAMEWORKS[target_arch]
        target_linkflags = TARGET_FLAGS[target_arch] + linkflags
        build_dir = os.path.join('stage',
                                 target_arch,
                                 ARGUMENTS.get('builddir', 'build'))
        for directory in DIRECTORIES:
            env = Environment(ARCH=target_arch,
                              CCFLAGS=target_ccflags,
                              CPPDEFINES=target_cppdefines,
                              LINKFLAGS=target_linkflags,
                              CONFIG_BUILDER=config_builder,
                              CONFIG_PARSER=config_parser,
                              FSTRACECHECK=fstracecheck,
                              PREFIX=prefix,
                              TARGET_FRAMEWORKS=target_frameworks,
                              tools=['default', 'textfile'])
            env['ARCHBUILDDIR'] = env.Dir('#stage/$ARCH/build').abspath
            if ar_override:
                env['AR'] = ar_override
            if cc_override:
                env['CC'] = cc_override
            if ranlib_override:
                env['RANLIB'] = ranlib_override
            if target_arch == "darwin":
                env.AppendENVPath("PATH", "/opt/local/bin")
            SConscript(dirs=directory,
                       exports=['env'],
                       duplicate=False,
                       variant_dir=os.path.join(build_dir, directory))
        Clean('.', build_dir)

if __name__ == 'SCons.Script':
    construct()
