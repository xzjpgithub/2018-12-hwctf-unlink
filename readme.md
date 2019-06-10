## double free的基本原理
```
FD = P->fd;
BK = P->bk;
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
    malloc_printerr (check_action, "corrupted double-linked list", P, AV);
else {
    FD->bk = BK;
    BK->fd = FD;
}
```
根据chunk的结构可知 `p->fd=p+0x10,p->bk=p+0x18`
所以上面代码就可以转换成
```
FD = P->fd; //FD = P + 0x10
BK = P->bk; //BK = P + 0x18
if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) //FD + 0x18 != P || BK + 0x10 != P  
    malloc_printerr (check_action, "corrupted double-linked list", P, AV);
else {
    FD->bk = BK; //FD + 0x18 = BK = P + 0x18
    BK->fd = FD; //BK + 0x10 = FD = P + 0x10
}
```
由于其中有 `FD->bk != P || BK->fd != P` 这个判断，所以最容易构造的场景就是找到一个指向P的指针A
```
P = FD->bk && P = BK->fd  ==> P = FD+0x18 && P = BK+0x10
P = FD+0x18 && P = BK+0x10 ==> P = P->fd + 0x18 && P = P->bk + 0x10
A = P //存在指向P的指针A
P = P->fd + 0x18 && P = P->bk + 0x10 ==> A = P->fd + 0x18 && A = P->bk + 0x10
A = P->fd + 0x18 && A = P->bk + 0x10 ==> A - 0x18 = P->fd && A - 0x10 = P->bk
```
推导的结论就是 `P->fd = A - 0x18  &&  P->bk = A - 0x10 ` 
能找到满足条件的A，并且将P的fd和bk填充成上述值，就能通过上面的double-linked list的检测
并且能将A的值改写成 
```
BK->fd = FD ==> P->bk->fd = P->fd 
            ==> P->bk = P 
            ==> A->bk = A 
            ==> A+0x18 = A
            ==> A = A - 0x18 //A最终会被赋值成A-0x18的值，这里=不是等，是赋值
```















