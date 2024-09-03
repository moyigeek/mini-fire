cmd_/home/moyi/ws/src/Module.symvers := sed 's/\.ko$$/\.o/' /home/moyi/ws/src/modules.order | scripts/mod/modpost -m -a  -o /home/moyi/ws/src/Module.symvers -e -i Module.symvers   -T -
