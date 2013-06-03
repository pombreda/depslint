#!/usr/bin/env python
#
# Copyright 2013 Maxim Kalaev
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Traces a ninja build step and prints out the dependencies found."""

import logging
import optparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(BASE_DIR, 'third_party', 'swarm_client'))

import trace_inputs  # pylint: disable=F0401


def which(program):
    """Implements the equivalent of 'which' bash command."""
    if sys.platform in ('cygwin', 'win32'):
        raise NotImplementedError('TODO(maruel)')
    for item in os.environ['PATH'].split(os.pathsep):
        if item and os.path.isdir(item):
            path = os.path.join(item, program)
            if os.access(path, os.X_OK):
                return path
    raise ValueError('Failed to find %s' % program)


def trace_build(api, cmd, cwd, logfile, targets):
    api.clean_trace(logfile)
    with api.get_tracer(logfile) as tracer:
        for target in targets:
            print('Tracing %s' % ' '.join(cmd))
            # TODO(maruel): Handle error code.
            tracer.trace(cmd + [target], cwd, 'ninja', False)
    return 0


def read_trace(api, root_dir, logname, outfile):
    """For now just dumps the raw unprocessed data.

    TODO(maruel): Detect ninja targets vs deps.
    """
    print('Reading')
    def blacklist(_path):
        return False
    data = api.parse_log(logname, blacklist, 'ninja')
    with file(outfile, 'wb') as f:
        for item in data:
            if 'exception' in item:
                # Do not abort the other traces.
                print >> sys.stderr, (
                    'Trace %s: Got an exception: %s' % (
                    item['trace'], item['exception'][1]))
                continue
            results = item['results']
            if root_dir:
                results = results.strip_root(root_dir)
            assert 'ninja' in results.process.executable
            # Consider all processes forked by ninja directly a 'build rule
            # process tree'. So only look at immediate 'ninja' child processes
            # and merge all the dependencies by their child processes into the
            # build rule.
            for process in results.process.children:
                logging.error('%d: %s', process.pid, process.command)
                files = sorted(
                        sum((p.files for p in process.all), []),
                        key=lambda x: x.path)
                i = [x.path for x in files
                        if x.existent and x.mode in ('r', 't')]
                o = [x.path for x in files if x.existent and x.mode == 'w']
                logging.error('  %d %d', len(i), len(o))
                if i and o:
                    f.write("{'OUT': %r, 'IN': %r, 'CMD': %r, 'PID': %r}\n" % (
                            o, i, process.command, [process.pid]))
    logging.info('Done')
    return 0


def main():
    parser = optparse.OptionParser(
        prog='depstrace',
        version='%prog: git',
        usage="usage: %prog [options] -- [command [arg ...]]",
        description=sys.modules[__name__].__doc__)
    parser.add_option(
        '-C', help='Relative path')
    parser.add_option(
        '--root-dir', help='Base path you care about')
    parser.add_option(
        '-l', '--logfile', default='deps.trc',
        help="store logs to the specified file [default: %default]")
    parser.add_option(
        '-o', '--outfile', default='deps.lst',
        help="store output to the specified file [default: %default]")
    parser.add_option(
        '-r', '--read_only', action='store_true',
        help='parse pre-recorded trace output instead of tracing the command')
    parser.add_option('-v', '--verbose', action='count', default=0)
    (options, args) = parser.parse_args()

    levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(
            level=levels[min(options.verbose, len(levels)-1)],
            format='%(message)s')

    options.logfile = os.path.abspath(options.logfile)
    if options.root_dir:
        options.root_dir = unicode(os.path.abspath(options.root_dir))

    try:
        api = trace_inputs.get_api()
        if not options.read_only:
            cmd = [which('ninja')]
            if options.C:
                cmd.extend(['-C', options.C])
            result = trace_build(
                api, cmd, os.getcwd(), options.logfile, args or ['all'])
            if result:
                return result

        return read_trace(
                api, options.root_dir, options.logfile, options.outfile)
    except KeyboardInterrupt:
        return 1


if __name__ == '__main__':
    sys.exit(main())

# vim: ts=4:sw=4:tw=80:et:
