echo "start committee_0"
cd committee_0
sh -x ./run.sh
cd ..
sleep 5

echo "start committee_1"
cd committee_1
sh -x ./run.sh
sleep 1

cd ..
echo "start operator_0"
sleep 1
cd operator_0
sh -x ./run.sh
cd ..

sleep 1
echo "start watchtower_0"
cd watchtower_0
sh -x ./run.sh
cd ..

sleep 1
echo "start verifier_0"
cd verifier_0
sh -x ./run.sh
cd ..