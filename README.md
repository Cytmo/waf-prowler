# waf-prowler
## REQUIREMENTS
`pip install -r requirements.txt`
## RUN 
### PARAMETERS
`-m` enable mutants
### SET UP TEST ENVS
Use `set_test_env.sh` to set up the test environments
### RUN TESTS
Use 'run.sh' to run the tests or run the following command:
`python3 main.py -m` to run the tests with mutants and memory
`python3 main.py -m --disable-memory` to run the tests with mutants and without memory
`python3 main.py --disable-memory -ds` to run the tests without memory and shortcut disabled


