cmd_/home/moyi/ws/module/Module.symvers := sed 's/\.ko$$/\.o/' /home/moyi/ws/module/modules.order | scripts/mod/modpost -m -a  -o /home/moyi/ws/module/Module.symvers -e -i Module.symvers   -T -
