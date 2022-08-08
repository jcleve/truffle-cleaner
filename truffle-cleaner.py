import json
import argparse

def main():

    # parse cmd line args
    parser = argparse.ArgumentParser(description='Scrub Trufflehog results')
    parser.add_argument('--file', type=str, required=True)
    parser.add_argument('--fail', default=False, action="store_true")
    args = parser.parse_args()

    # process trufflehog findings
    parsed = []
    pre_parsed = 0
    post_parsed = 0
    with open(args.file) as f:
        data = json.load(f)
        for d in data:
            pre_parsed+=1
            if d['Redacted'] == "":
                continue
            else:
                post_parsed+=1
                parsed.append(d)

    # print basic findings
    print("Total Results before parsing: " + str(pre_parsed))
    print("Total Results after parsing: " + str(post_parsed))
    print("Writing 'parsed.json'...")

    # write parsed results file. (this logic is super fuzzy, but so is TruffleHog's)
    with open(r'parsed.json', 'w') as fp:
        json_string = json.dumps(parsed)
        fp.write(json_string)
        print('Done')

    # fail if secrets are detected
    if post_parsed > 0 and args.fail:
        raise RuntimeError('Exposed secrets detected')

if __name__ == "__main__":
    main()