import hashlib,json,pathlib,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]).resolve();art=root/'artifact';run=json.loads((root/'run-final.json').read_text());sha=run['head_sha']
paths=subprocess.check_output(['git','ls-tree','-r','--name-only',sha,'--','scripts','.github/workflows/n2-functional.yml','Cargo.lock','web/pnpm-lock.yaml','docs/design/n2/linux-docker-20261025/images/frozen.json'],text=True).splitlines()
with tempfile.TemporaryDirectory(prefix='n2-frozen-audit-') as temporary:
 base=pathlib.Path(temporary)
 for name in paths:
  relative=pathlib.PurePosixPath(name);assert not relative.is_absolute() and '..' not in relative.parts
  p=base.joinpath(*relative.parts);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(subprocess.check_output(['git','show',sha+':'+name]))
 sys.path.insert(0,str(base/'scripts'));import run_management_n2_ci as frozen
 expected=frozen.tool_manifest();actual=json.loads((art/'tool-manifest.json').read_text());assert actual==expected
 frozen.validate_publication(art);summary=json.loads((art/'final-summary.json').read_text());full=summary['status']=='passed'
 if full:frozen.validate_suite_evidence(art,summary['source'])
 result={'executionSha':sha,'validatorLoadedFromGitSha':sha,'frozenToolInputsMatched':len(expected),'publication':'passed','eightSuiteValidation':'passed' if full else 'not_complete','unrelatedWorkingTreeUsed':False}
 (root/'frozen-validator-review.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
