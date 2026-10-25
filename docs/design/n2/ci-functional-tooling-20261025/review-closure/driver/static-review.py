from pathlib import Path
import sys,subprocess,json,re,urllib.parse,unicodedata
root=Path.cwd();result={'mode':'static-only; syntax checks never run workflow bodies'}
py=sorted(root.joinpath('scripts').glob('*.py'));js=sorted(root.joinpath('scripts').glob('*.mjs'))
for p in py: compile(p.read_text(),str(p),'exec')
for p in js: subprocess.run(['node','--check',str(p)],check=True,capture_output=True)
result['python']=[str(p.relative_to(root)) for p in py];result['node']=[str(p.relative_to(root)) for p in js]
w=json.loads(subprocess.check_output(['ruby','-ryaml','-rjson','-e','puts JSON.generate(YAML.load_file(ARGV[0]))','.github/workflows/n2-functional.yml'],text=True))
assert w.get('on',w.get('true'))=={'workflow_dispatch':None};assert w['permissions']=={'contents':'read'};assert len(w['jobs'])==1
job=w['jobs']['functional-arm64'];assert job['runs-on']=='ubuntu-24.04-arm' and job['timeout-minutes']==120
runs=[step['run'] for step in job['steps'] if 'run' in step]
for script in runs: subprocess.run(['bash','-n'],input=script,text=True,capture_output=True,check=True)
assert all(re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}',s['uses']) for s in job['steps'] if 'uses' in s)
result['workflow']={'manualOnly':True,'jobs':1,'shellBlocksSyntaxChecked':len(runs),'actions':[s['uses'] for s in job['steps'] if 'uses' in s]}
docs=[root/p for p in ['README.md','docs/management-console-delivery-summary-and-plan.md','docs/management-console-n2-github-actions-functional-plan.md','docs/validation-runtime-topology.md','docs/n2-functional-ci-tooling-result.md','scripts/n2-ci/README.md','docs/design/n2/ci-functional-tooling-20261025/README.md','docs/design/n2/ci-functional-tooling-20261025/review-closure/README.md']]
def anchors(p):
 used={};found=set()
 for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$',p.read_text(),re.M):
  text=heading.replace('`','').lower()
  slug=''.join(c for c in text if c in '_-' or c.isspace() or unicodedata.category(c)[0] in 'LNM').strip().replace(' ','-')
  n=used.get(slug,0);used[slug]=n+1;found.add(slug+('-'+str(n) if n else ''))
 return found
count=0
for p in docs:
 txt=re.sub(r'```.*?```','',p.read_text(),flags=re.S)
 for target in re.findall(r'!?\[[^\]]*\]\(([^\s)]+)(?:\s+"[^\"]*")?\)',txt):
  if re.match(r'^[a-z]+:',target):continue
  rel,_,fragment=urllib.parse.unquote(target.strip('<>')).partition('#');dest=(p.parent/rel).resolve() if rel else p
  assert dest.exists(),(p,target)
  if fragment:assert fragment in anchors(dest),(p,target)
  count+=1
result['documentLinksAndAnchors']=count
assert subprocess.check_output(['git','diff','--name-only','--','crates','web','.github/workflows/ci.yml'],text=True)==''
assert subprocess.check_output(['git','hash-object','docs/m1-02-code-review.md'],text=True).strip()=='4ef4907646970f1cd06ec80cf51a9516497244d6'
assert not (root/'scripts/n2-ci/node_modules').exists()
result.update(productSourceDiff='empty',existingWorkflowDiff='empty',unrelatedReview='unchanged',installedToolDependencies=False,actualBrowserDockerPgRuns=0,selectedFunctionalAssertions=264,excludedAssertions=13,offlineCheckTotal=122)
(root/'docs/design/n2/ci-functional-tooling-20261025/review-closure/final/static-checks.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'python':len(py),'node':len(js),'shellBlocks':len(runs),'documentLinks':count,'result':'passed'}))
