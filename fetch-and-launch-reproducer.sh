# Environment variables needed:
# - TUXSUITE_TOKEN - the token to submit tuxsuite reproducer

TESTRUN=$1
REPRODUCER=$2
pip install -r requirements.txt
inputs="--testrun $TESTRUN --filename $REPRODUCER"
echo $inputs
python validate-inputs.py $inputs
python squad-create-reproducer-from-testrun $inputs --plan
tuxsuite plan $REPRODUCER