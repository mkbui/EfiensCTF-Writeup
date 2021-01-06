.data
	hello_txt:			.asciiz "\n input flag: \n"
	fail_txt:			.asciiz "\n Fail!!!\n"
	success_txt:		.asciiz "\n Congratulations!!!\n"
	flag:				.word 30

.text

main:
	li $v0, 4
	la $a0, hello_txt
	syscall
	
	li $v0, 8
	la $a0, flag
	li $a1, 30
	syscall
	
	move $a1, $a0
	
	move $a0, $a1
	jal func0
	move $t1, $v0
	
	bne $t1, 27, label0
	
	move $a0, $a1
	jal func1
	move $t1, $v0
	
	bne $t1, 1, label0
	j label1
label0:
	li $v0, 4
	xor $a0, $a0, $a0
	la $a0, fail_txt
	syscall
	j exit
	
label1:
	li $v0, 4
	xor $a0, $a0, $a0
	la $a0, success_txt
	syscall
	

exit:
	li $v0, 10
	syscall


func0:
	add $t0, $a0, $zero
	xor $v0, $v0, $v0
	
  loop1:
	lbu  $t1, 0($t0)
	beq  $t1, 10, endloop1
	
	addi $t0, $t0, 1
	addi $v0, $v0, 1
	j loop1
	
  endloop1:
    
	jr $ra

func1:
	add $t0, $a0, $zero
	addi $t3, $zero, 97
	
	addi $t1, $zero, 937
	addi $t1, $t1, 847
	addi $t1, $t1, -1758
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 222, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 186
	addi $t1, $t1, 630
	addi $t1, $t1, -791
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 27, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 860
	addi $t1, $t1, 356
	addi $t1, $t1, -1192
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, 16, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 732
	addi $t1, $t1, 235
	addi $t1, $t1, -944
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 164, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 804
	addi $t1, $t1, 791
	addi $t1, $t1, -1573
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 86, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 583
	addi $t1, $t1, 326
	addi $t1, $t1, -888
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, -7, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 240
	addi $t1, $t1, 927
	addi $t1, $t1, -1147
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 151, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 202
	addi $t1, $t1, 535
	addi $t1, $t1, -718
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 88, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 951
	addi $t1, $t1, 416
	addi $t1, $t1, -1349
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, 11, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 142
	addi $t1, $t1, 272
	addi $t1, $t1, -397
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 201, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 326
	addi $t1, $t1, 591
	addi $t1, $t1, -901
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 24, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 248
	addi $t1, $t1, 816
	addi $t1, $t1, -1049
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, -75, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 649
	addi $t1, $t1, 331
	addi $t1, $t1, -966
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 204, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 153
	addi $t1, $t1, 526
	addi $t1, $t1, -666
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 29, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 192
	addi $t1, $t1, 950
	addi $t1, $t1, -1130
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, 1, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 827
	addi $t1, $t1, 967
	addi $t1, $t1, -1783
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 145, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 566
	addi $t1, $t1, 426
	addi $t1, $t1, -982
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 28, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 750
	addi $t1, $t1, 439
	addi $t1, $t1, -1180
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, 9, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 937
	addi $t1, $t1, 489
	addi $t1, $t1, -1418
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 217, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 278
	addi $t1, $t1, 322
	addi $t1, $t1, -593
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 0, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 944
	addi $t1, $t1, 417
	addi $t1, $t1, -1355
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, -18, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 860
	addi $t1, $t1, 133
	addi $t1, $t1, -988
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 233, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 602
	addi $t1, $t1, 362
	addi $t1, $t1, -960
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 25, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 804
	addi $t1, $t1, 454
	addi $t1, $t1, -1255
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, -19, ret0

	addi $t3, $t3, 1
	

	addi $t1, $zero, 792
	addi $t1, $t1, 675
	addi $t1, $t1, -1465
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	add $t4, $t2, $t3
	bne, $t4, 226, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 459
	addi $t1, $t1, 907
	addi $t1, $t1, -1365
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	xor $t4, $t2, $t3
	bne, $t4, 28, ret0
	addi $t3, $t3, 1
	

	addi $t1, $zero, 803
	addi $t1, $t1, 891
	addi $t1, $t1, -1694
	add $t1, $t1, $a0
	lbu $t2, 0($t1)
	sub $t4, $t2, $t3
	bne, $t4, -22, ret0
	

	addi $v0, $zero, 1
	jr $ra
	
	ret0:
	xor $v0, $v0, $v0
	jr $ra


	
	
	
	


	
	
