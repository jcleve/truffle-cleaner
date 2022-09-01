import json
import yaml
import argparse
from os.path import exists
from os.path import basename

def main():

    # parse cmd line args
    parser = argparse.ArgumentParser(description='Scrub Trufflehog results')
    parser.add_argument('--file', type=str, required=True)
    parser.add_argument('--fail', default=False, action="store_true")
    parser.add_argument('--exclude', type=str)
    args = parser.parse_args()

    #  vars
    parsed = []
    excluded = []
    pre_parsed = 0
    post_parsed = 0

    # load allow list
    if args.exclude is not None and exists(args.exclude):
        with open(args.exclude, 'r') as stream:
            exclusions = yaml.safe_load(stream)
            for file in exclusions:
                excluded.append(file)
        print('Excluded files: ' + str(excluded))
    else:
        print('No exclusion file passed...\n')

    # process trufflehog findings
    with open(args.file) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]

        for line in lines:
            data = json.loads(line)
            pre_parsed+=1
            if data['Redacted'] == "":
                continue
            # ignore files added to exclude/allow list
            if basename(data['SourceMetadata']['Data']['Filesystem']['file']) in excluded:
                continue
            else:
                post_parsed+=1
                parsed.append(data)
                print(line + '\n')

    # print basic findings
    print("Total Results before scrubbing: " + str(pre_parsed))
    print("Total Results after scrubbing: " + str(post_parsed))

    # write parsed results file. (this logic is super fuzzy, but so is TruffleHog's)
    # with open(r'parsed.json', 'w') as fp:
    #   json_string = json.dumps(parsed)
    #    fp.write(json_string)
    #    print('Done')

    # fail if secrets are detected
    if post_parsed > 0 and args.fail:
        raise RuntimeError('Exposed secrets detected')


if __name__ == "__main__":
    main()


