class A{
    public:
    int counter;
    A() {
        counter = 0;
    }
    virtual void ink() {
        counter++;
    }
    virtual void dek() {
        counter--;
    }
};

class B{
    public:
    int data = 0;
    A *subclass[3];
    B() {
        for(int i= 0;i<3; i++) {
            subclass[i];
        }
    }
    virtual void incA() {
        for(int i= 0;i<3; i++) {
            subclass[i]->dek();
        }
    }

};

int main() {
    B *b = new B();
    b->incA();
    return 0;
}
