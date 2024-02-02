import itertools
import os

def log_processor(test_id,log_file):
    # circuit summary prefix, degree, max_num_row,
    CIRCUIT_SUMMARY = "[Circuit summary]"
    #generate witness , gw
    GENERATE_WITNESS= "[Generate witness]"
    #create circuit ,cc
    CREATE_CIRCUIT = "[Create circuit]"
    # setup generation ,sg
    SETUP_GENERATION = "[Setup generation]"
    # verify proof , vp
    VERIFY_PROOF = "[Verify proof]"
    # create proof cp
    CREATE_PROOF = "[Create_proof]"
    MAX_NUM_ROW = "max_num_row"
    DEGREE = "degree"
    f = open(log_file,'r')
    logdata = f.read()
    logdata = logdata.split("\n")
    # 解析circuit summary
    for spl in  [i for i in logdata if CIRCUIT_SUMMARY in i][0].split(","): 

        if MAX_NUM_ROW in spl:
            max_num_row = spl.lstrip().rstrip().removeprefix(MAX_NUM_ROW+":")
        elif DEGREE in spl:
            degree = spl.lstrip().rstrip().removeprefix(DEGREE+":")
    # 解析每个步骤的耗时 
    running = [i for i in logdata if 'running' in i and 'test' in i][0].split()[1]
    if running != '0':
        r = [i.split(":")[1].split(".")[0].replace(" ","") for i in logdata if 'test result' in i][0]
        if r == 'ok':
            result = "Passed"
            # 解析generate_witness时间
            try:
                for kk in [i for i in logdata if 'End' in i and  GENERATE_WITNESS in i]:
                    generate_witness = kk.split(" ")[-1]
                    generate_witness = process_nums(generate_witness)
            except:
                generate_witness = None
            # 解析create_circuit时间
            try:
                create_circuit = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and CREATE_CIRCUIT in i ][0])).split('.', 1)[-1]
                create_circuit = process_nums(create_circuit)
            except:
                create_circuit = None
            # 解析setup generation时间
            try:
                setup_generation = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and SETUP_GENERATION in i ][0])).split('.', 1)[-1]
                setup_generation = process_nums(setup_generation)
            except:
                setup_generation = None
            # 解析verify proof时间
            try:
                verify_proof = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and VERIFY_PROOF in i ][0])).split('.', 1)[-1]
                verify_proof = process_nums(verify_proof)
            except:
                verify_proof = None
            # 解析crate proof时间
            try:
                create_proof =  ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and CREATE_PROOF in i ][0])).split('.', 1)[-1]
                create_proof = process_nums(create_proof)
            except:
                create_proof = None
            ret_data = {
                'test_id': test_id,
                'degree': degree,
                'max_num_row':max_num_row,
                'witness_gen': generate_witness,
                'circuit_create': create_circuit, 
                'setup_gen': setup_generation,
                'verify_proof': verify_proof,
                'create_proof': create_proof,
                'result': result,
            }
        else:
            result = "Failed"
            ret_data = {
                'test_id': test_id,
                'degree': degree,
                'max_num_row':max_num_row,
                'witness_gen': None,
                'circuit_create': None,  
                'setup_gen': None,
                'verify_proof': None,
                'create_proof': None,
                'result': result,
            }            

    else:
        result = 'None'
        ret_data = {
            'test_id': test_id,
            'degree': degree,
            'max_num_row':max_num_row,
            'witness_gen': None,
            'circuit_create': None,  
            'setup_gen': None,
            'verify_proof': None,
            'create_proof': None,
            'result': result,
        }
    return ret_data 

def process_nums(original_data):
    original_data = original_data.strip()
    if original_data.count('.') >1 and original_data.startswith('.'):
        ret_data = original_data.lstrip('.')    
    elif original_data.count('.') == 1  and original_data.startswith('.'):
        ret_data = '0' + original_data    
    else:
        ret_data = original_data
    print("original: %s,ret: %s"%(original_data,ret_data))
    return ret_data